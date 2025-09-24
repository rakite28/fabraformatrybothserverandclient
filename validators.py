from pydantic import BaseModel, EmailStr, Field, validator
from typing import List, Optional

# --- AUTHENTICATION & USER MANAGEMENT ---

class LoginModel(BaseModel):
    identifier: str
    password: str
    remember_me: bool = False

class RefreshTokenModel(BaseModel):
    remember_token: str

class RegisterCompanyModel(BaseModel):
    company_name: str = Field(..., min_length=1, description="Company name must not be empty.")
    admin_username: str = Field(..., min_length=3, description="Username must be at least 3 characters long.")
    admin_email: EmailStr
    admin_password: str = Field(..., min_length=8, description="Password must be at least 8 characters long.")

class CreateUserModel(BaseModel):
    username: str = Field(..., min_length=3, description="Username must be at least 3 characters long.")
    email: EmailStr
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long.")
    role: str

    @validator('role')
    def role_must_be_valid(cls, v):
        if v not in ['admin', 'user']:
            raise ValueError("Role must be either 'admin' or 'user'")
        return v

class ChangePasswordModel(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, description="New password must be at least 8 characters long.")

class UpdateProfileModel(BaseModel):
    username: Optional[str] = Field(None, min_length=3)
    phone_number: Optional[str] = None
    dob: Optional[str] = None # Can be improved with date parsing if strict format is needed

# --- DATA MANAGEMENT ---

class PrinterModel(BaseModel):
    id: str
    brand: str = Field(..., min_length=1)
    model: str = Field(..., min_length=1)
    setup_cost: float = Field(..., ge=0, description="Setup cost must be zero or greater.")
    maintenance_cost: float = Field(..., ge=0, description="Maintenance cost must be zero or greater.")
    lifetime_years: int = Field(..., ge=1, description="Lifetime must be at least 1 year.")
    power_w: float = Field(..., ge=0, description="Power must be zero or greater.")
    price_kwh: float = Field(..., ge=0, description="Price/kWh must be zero or greater.")
    buffer_factor: float = Field(..., ge=1.0, description="Buffer factor must be 1.0 or greater.")
    uptime_percent: float = Field(..., ge=0, le=100, description="Uptime must be between 0 and 100.")

class FilamentsPostModel(BaseModel):
    price: float = Field(..., ge=0, description="Price must be zero or greater.")
    stock_g: float = Field(..., ge=0, description="Stock must be zero or greater.")
    efficiency_factor: float = Field(..., gt=0, description="Efficiency factor must be greater than zero.")

# --- CORE LOGIC ---

class ProcessImageModel(BaseModel):
    filename: str = Field(..., min_length=1, alias='Filename')
    filament_g: float = Field(..., ge=0, alias='Filament (g)')
    time_str: str = Field(..., min_length=1, alias='Time (e.g. 7h 30m)')
    timestamp: str 
    printer_id: str
    printer_name: str = Field(..., alias='Printer')
    material: str = Field(..., alias='Material')
    brand: str = Field(..., alias='Brand')
    filament_cost_kg: float = Field(..., ge=0, alias='Filament Cost (₹/kg)')
    labour_time_min: int = Field(..., ge=0, alias='Labour Time (min)')
    labour_rate_hr: float = Field(..., ge=0, alias='Labour Rate (₹/hr)')

    class Config:
        allow_population_by_field_name = True

class QuotationPartModel(BaseModel):
    name: str
    cogs: float = Field(..., ge=0)

class CompanyDetailsModel(BaseModel):
    name: str
    address: str
    contact: str
    logo_path: Optional[str] = None

class GenerateQuotationModel(BaseModel):
    customer_name: str = Field(..., min_length=1)
    customer_company: Optional[str] = None
    parts: List[QuotationPartModel]
    margin_percent: float = Field(..., ge=0)
    tax_rate_percent: float = Field(..., ge=0)
    company_details: CompanyDetailsModel

# --- SLICER FEATURE MODELS ---

class SliceRequestModel(BaseModel):
    """Validates the JSON data sent with an STL file for slicing."""
    machine_profile: str = Field(..., min_length=1, description="A machine profile filename is required.")
    filament_profile: str = Field(..., min_length=1, description="A filament profile filename is required.")
    process_profile: str = Field(..., min_length=1, description="A process (quality) profile filename is required.")

class SlicerProfileModel(BaseModel):
    """Provides basic validation for an uploaded slicer profile .json file."""
    type: str
    name: str

    @validator('type')
    def type_must_be_valid(cls, v):
        if v not in ['machine', 'filament', 'process']:
            raise ValueError("Profile type must be 'machine', 'filament', or 'process'")
        return v

