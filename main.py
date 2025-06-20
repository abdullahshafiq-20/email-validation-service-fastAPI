from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr, Field
import smtplib
import socket
import dns.resolver
import re
from typing import Dict, Optional, Any, List, Tuple
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import time
from concurrent.futures import ThreadPoolExecutor

app = FastAPI(
    title="Email SMTP Validator API",
    description="API to validate email addresses and check SMTP server availability",
    version="1.0.0"
)

class EmailRequest(BaseModel):
    email: EmailStr

class EmailValidationResponse(BaseModel):
    email: str
    is_valid_format: bool
    domain: str
    mx_records: Optional[list] = None
    smtp_server_exists: bool
    smtp_server_responsive: bool
    smtp_accepts_mail: bool
    error_message: Optional[str] = None
    validation_details: Dict[str, Any] = {}

# NEW: Bulk validation models
class BulkEmailRequest(BaseModel):
    emails: List[EmailStr] = Field(..., min_items=1, max_items=100, description="List of emails to validate (max 100)")
    max_workers: Optional[int] = Field(default=10, ge=1, le=20, description="Number of parallel workers for validation")

class BulkEmailValidationResponse(BaseModel):
    total_emails: int
    processed_emails: int
    valid_emails: int
    invalid_emails: int
    processing_time: float
    results: List[EmailValidationResponse]
    summary: Dict[str, Any]

class SMTPValidator:
    def __init__(self):
        # Aggressive timeouts for faster responses
        self.connection_timeout = 5
        self.smtp_timeout = 3
        self.max_mx_servers_to_try = 3
        
    def validate_email_format(self, email: str) -> bool:
        """Basic email format validation"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def get_domain_from_email(self, email: str) -> str:
        """Extract domain from email address"""
        return email.split('@')[1]
    
    def get_mx_records_sorted(self, domain: str) -> List[Tuple[int, str]]:
        """Get MX records sorted by priority (lower number = higher priority)"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            # Parse and sort by priority
            mx_list = []
            for mx in mx_records:
                priority, server = str(mx).split(' ', 1)
                mx_list.append((int(priority), server.rstrip('.')))
            
            # Sort by priority (lower number first)
            mx_list.sort(key=lambda x: x[0])
            return mx_list
        except Exception:
            return []
    
    def test_smtp_connection(self, mx_server: str) -> Tuple[bool, str]:
        """Test basic SMTP connection with fast timeout"""
        try:
            # Quick socket test first
            sock = socket.create_connection((mx_server, 25), timeout=self.connection_timeout)
            sock.close()
            return True, f"Connection to {mx_server} successful"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
    
    def comprehensive_smtp_check(self, email: str, mx_server: str) -> Tuple[bool, bool, bool, str]:
        """
        Comprehensive SMTP check using single connection
        Returns: (server_exists, server_responsive, accepts_mail, message)
        """
        try:
            # Create SMTP connection with timeout
            server = smtplib.SMTP(timeout=self.smtp_timeout)
            server.set_debuglevel(0)  # Disable debug for speed
            
            # Connect to SMTP server
            code, msg = server.connect(mx_server, 25)
            if code != 220:
                server.quit()
                return True, False, False, f"Server connect failed: {code} {msg}"
            
            server_exists = True
            
            # Test HELO/EHLO command
            try:
                code, msg = server.ehlo()
                if code not in [250, 502]:  # 502 means EHLO not supported, try HELO
                    code, msg = server.helo()
                
                if code != 250:
                    server.quit()
                    return server_exists, False, False, f"HELO failed: {code}"
                
                server_responsive = True
            except Exception as e:
                server.quit()
                return server_exists, False, False, f"HELO error: {str(e)}"
            
            # Test MAIL FROM command
            try:
                code, msg = server.mail('test@example.com')
                if code != 250:
                    server.quit()
                    return server_exists, server_responsive, False, f"MAIL FROM rejected: {code}"
            except Exception as e:
                server.quit()
                return server_exists, server_responsive, False, f"MAIL FROM error: {str(e)}"
            
            # Test RCPT TO command (the actual email validation)
            try:
                code, msg = server.rcpt(email)
                server.quit()
                
                if code in [250, 251]:  # 250 = OK, 251 = User not local but will forward
                    return server_exists, server_responsive, True, f"Email accepted: {code}"
                elif code in [450, 451, 452]:  # Temporary failures
                    return server_exists, server_responsive, False, f"Temporary failure: {code} {msg}"
                else:  # Permanent failures (550, 551, 552, 553, etc.)
                    return server_exists, server_responsive, False, f"Email rejected: {code} {msg}"
                    
            except Exception as e:
                server.quit()
                return server_exists, server_responsive, False, f"RCPT TO error: {str(e)}"
                
        except socket.timeout:
            return False, False, False, "SMTP connection timed out"
        except Exception as e:
            return False, False, False, f"SMTP error: {str(e)}"
    
    def validate_email_smtp_focused(self, email: str) -> EmailValidationResponse:
        """
        SMTP-focused email validation with multiple MX server attempts
        """
        start_time = time.time()
        
        # Quick format check
        is_valid_format = self.validate_email_format(email)
        if not is_valid_format:
            return EmailValidationResponse(
                email=email,
                is_valid_format=False,
                domain="",
                mx_records=[],
                smtp_server_exists=False,
                smtp_server_responsive=False,
                smtp_accepts_mail=False,
                error_message="Invalid email format",
                validation_details={"validation_time": time.time() - start_time}
            )
        
        domain = self.get_domain_from_email(email)
        
        # Get MX records
        mx_records_sorted = self.get_mx_records_sorted(domain)
        mx_records_display = [f"{priority} {server}" for priority, server in mx_records_sorted]
        
        if not mx_records_sorted:
            return EmailValidationResponse(
                email=email,
                is_valid_format=True,
                domain=domain,
                mx_records=[],
                smtp_server_exists=False,
                smtp_server_responsive=False,
                smtp_accepts_mail=False,
                error_message="No MX records found for domain",
                validation_details={"validation_time": time.time() - start_time}
            )
        
        # Try multiple MX servers (starting with highest priority)
        validation_details = {
            "mx_count": len(mx_records_sorted),
            "servers_tried": [],
            "validation_time": 0
        }
        
        last_error = "No servers responded"
        
        for i, (priority, mx_server) in enumerate(mx_records_sorted[:self.max_mx_servers_to_try]):
            server_attempt = {
                "server": mx_server,
                "priority": priority,
                "attempt": i + 1
            }
            
            # Quick connection test first
            can_connect, connect_msg = self.test_smtp_connection(mx_server)
            server_attempt["connection_test"] = connect_msg
            
            if not can_connect:
                server_attempt["result"] = "connection_failed"
                validation_details["servers_tried"].append(server_attempt)
                last_error = connect_msg
                continue
            
            # Comprehensive SMTP check
            smtp_exists, smtp_responsive, smtp_accepts, message = self.comprehensive_smtp_check(email, mx_server)
            
            server_attempt.update({
                "smtp_exists": smtp_exists,
                "smtp_responsive": smtp_responsive,
                "smtp_accepts": smtp_accepts,
                "message": message,
                "result": "success" if smtp_accepts else "failed"
            })
            
            validation_details["servers_tried"].append(server_attempt)
            
            # If we got a definitive answer (positive or negative), return it
            if smtp_exists and smtp_responsive:
                validation_details["validation_time"] = time.time() - start_time
                validation_details["successful_server"] = mx_server
                
                return EmailValidationResponse(
                    email=email,
                    is_valid_format=True,
                    domain=domain,
                    mx_records=mx_records_display,
                    smtp_server_exists=smtp_exists,
                    smtp_server_responsive=smtp_responsive,
                    smtp_accepts_mail=smtp_accepts,
                    error_message=None if smtp_accepts else message,
                    validation_details=validation_details
                )
            
            last_error = message
        
        # All servers failed
        validation_details["validation_time"] = time.time() - start_time
        
        return EmailValidationResponse(
            email=email,
            is_valid_format=True,
            domain=domain,
            mx_records=mx_records_display,
            smtp_server_exists=False,
            smtp_server_responsive=False,
            smtp_accepts_mail=False,
            error_message=f"All SMTP servers failed. Last error: {last_error}",
            validation_details=validation_details
        )

    # NEW: Bulk validation method
    def validate_emails_bulk(self, emails: List[str], max_workers: int = 10) -> BulkEmailValidationResponse:
        """
        Validate multiple emails in parallel with thread pool
        """
        start_time = time.time()
        
        # Remove duplicates while preserving order
        unique_emails = list(dict.fromkeys(emails))
        total_emails = len(unique_emails)
        
        results = []
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all validation tasks
            future_to_email = {
                executor.submit(self.validate_email_smtp_focused, email): email 
                for email in unique_emails
            }
            
            # Collect results as they complete
            for future in future_to_email:
                try:
                    result = future.result(timeout=30)  # 30-second timeout per email
                    results.append(result)
                except Exception as e:
                    email = future_to_email[future]
                    # Create error response for failed validation
                    error_response = EmailValidationResponse(
                        email=email,
                        is_valid_format=False,
                        domain="",
                        mx_records=[],
                        smtp_server_exists=False,
                        smtp_server_responsive=False,
                        smtp_accepts_mail=False,
                        error_message=f"Validation timeout or error: {str(e)}",
                        validation_details={"error": str(e)}
                    )
                    results.append(error_response)
        
        # Calculate statistics
        processing_time = time.time() - start_time
        valid_emails = sum(1 for r in results if r.smtp_accepts_mail)
        invalid_emails = total_emails - valid_emails
        
        # Generate summary statistics
        domains = {}
        error_types = {}
        
        for result in results:
            # Domain statistics
            domain = result.domain if result.domain else "unknown"
            if domain not in domains:
                domains[domain] = {"total": 0, "valid": 0, "invalid": 0}
            domains[domain]["total"] += 1
            if result.smtp_accepts_mail:
                domains[domain]["valid"] += 1
            else:
                domains[domain]["invalid"] += 1
            
            # Error type statistics
            if result.error_message:
                error_type = result.error_message.split(':')[0] if ':' in result.error_message else result.error_message
                error_types[error_type] = error_types.get(error_type, 0) + 1
        
        summary = {
            "unique_emails_processed": len(unique_emails),
            "duplicate_emails_removed": len(emails) - len(unique_emails),
            "domains_processed": len(domains),
            "domain_breakdown": domains,
            "error_breakdown": error_types,
            "average_validation_time": processing_time / total_emails if total_emails > 0 else 0,
            "success_rate": (valid_emails / total_emails * 100) if total_emails > 0 else 0
        }
        
        return BulkEmailValidationResponse(
            total_emails=total_emails,
            processed_emails=len(results),
            valid_emails=valid_emails,
            invalid_emails=invalid_emails,
            processing_time=processing_time,
            results=results,
            summary=summary
        )

# Initialize validator
validator = SMTPValidator()

@app.get("/")
async def root():
    return {
        "message": "SMTP-Focused Email Validator API",
        "version": "2.0.0",
        "endpoints": {
            "validate": "/validate-email",
            "validate-get": "/validate-email/{email}",
            "bulk-validate": "/validate-emails-bulk",
            "quick-check": "/quick-check/{email}",
            "health": "/health"
        }
    }

@app.post("/validate-email", response_model=EmailValidationResponse)
async def validate_email(request: EmailRequest):
    """
    SMTP-focused email validation with multiple server attempts
    """
    try:
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, 
            validator.validate_email_smtp_focused, 
            request.email
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")

@app.get("/validate-email/{email}")
async def validate_email_get(email: str):
    """
    SMTP-focused email validation via GET request
    """
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, 
            validator.validate_email_smtp_focused, 
            email
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")

# NEW: Bulk validation endpoint
@app.post("/validate-emails-bulk", response_model=BulkEmailValidationResponse)
async def validate_emails_bulk(request: BulkEmailRequest):
    """
    Validate multiple emails in parallel with comprehensive SMTP checking
    
    Features:
    - Parallel processing with configurable worker threads
    - Duplicate email removal
    - Comprehensive statistics and domain breakdown
    - Error categorization and reporting
    - Timeout handling for individual validations
    
    Limits:
    - Maximum 100 emails per request
    - Maximum 20 parallel workers
    - 30-second timeout per email validation
    """
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            validator.validate_emails_bulk,
            request.emails,
            request.max_workers
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk validation error: {str(e)}")

@app.get("/quick-check/{email}")
async def quick_smtp_check(email: str):
    """
    Quick SMTP connection test only
    """
    try:
        domain = validator.get_domain_from_email(email)
        mx_records = validator.get_mx_records_sorted(domain)
        
        if not mx_records:
            return {
                "email": email,
                "domain": domain,
                "mx_records_count": 0,
                "smtp_server_exists": False,
                "message": "No MX records found"
            }
        
        # Test connection to primary MX server only
        primary_mx = mx_records[0][1]
        can_connect, message = validator.test_smtp_connection(primary_mx)
        
        return {
            "email": email,
            "domain": domain,
            "mx_records_count": len(mx_records),
            "primary_mx_server": primary_mx,
            "smtp_server_exists": can_connect,
            "message": message
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Quick check error: {str(e)}")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "smtp-email-validator"}

if __name__ == "__main__":
    import uvicorn
    import os
    
    # Get port from environment variable (Render sets this) or default to 8000
    port = int(os.environ.get("PORT", 8000))
    
    uvicorn.run(app, host="0.0.0.0", port=port)