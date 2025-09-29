import os
from datetime import datetime
from flask import current_app
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import utils, colors

def generate_quotation_pdf(buffer, data):
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    comp_details = data.get("company_details", {})

    # Draw Logo
    if comp_details.get("logo_path") and os.path.exists(comp_details["logo_path"]):
        try:
            img = utils.ImageReader(comp_details["logo_path"])
            i_width, i_height = img.getSize()
            aspect = i_height / float(i_width)
            c.drawImage(img, 40, height - 100, width=80, height=(80 * aspect))
        except Exception as e:
            current_app.logger.error(f"Could not draw logo on PDF: {e}")

    # Company Details
    c.setFont("Helvetica-Bold", 16)
    c.drawRightString(width - 50, height - 60, comp_details.get("name", "Your Company"))
    c.setFont("Helvetica", 10)
    c.drawRightString(width - 50, height - 75, comp_details.get("address", "Company Address"))
    c.drawRightString(width - 50, height - 90, comp_details.get("contact", "Contact Info"))

    # Title
    c.setFont("Helvetica-Bold", 24)
    c.drawString(50, height - 150, "Quotation")
    c.line(50, height - 155, width - 50, height - 155)

    # Billed To
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 190, "BILLED TO:")
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 205, data.get("customer_name", "Valued Customer"))
    if data.get("customer_company"):
        c.drawString(50, height - 220, data.get("customer_company"))

    # Date
    c.setFont("Helvetica", 12)
    c.drawRightString(width - 50, height - 190, f"Date: {datetime.now().strftime('%Y-%m-%d')}")

    # Table Header
    y_position = height - 260
    c.setFont("Helvetica-Bold", 11)
    c.drawString(60, y_position, "Part Description")
    c.drawRightString(width - 200, y_position, "Unit Price")
    c.drawRightString(width - 50, y_position, "Total")
    c.line(50, y_position - 10, width - 50, y_position - 10)
    y_position -= 30

    # Pricing Calculation
    total_cogs = sum(part.get("cogs", 0) for part in data["parts"])
    margin_percent = data.get("margin_percent", 0)
    subtotal = total_cogs / (1 - (margin_percent / 100.0)) if margin_percent < 100 else 0
    tax_rate_percent = data.get("tax_rate_percent", 0)
    tax_amount = subtotal * (tax_rate_percent / 100.0)
    grand_total = subtotal + tax_amount

    # Line Items
    c.setFont("Helvetica", 10)
    line_item_description = f"{len(data['parts'])} Custom Manufactured Part(s)"
    c.drawString(60, y_position, line_item_description)
    c.drawRightString(width - 200, y_position, f"Rs{subtotal:,.2f}")
    c.drawRightString(width - 50, y_position, f"Rs{subtotal:,.2f}")
    y_position -= 30
    c.line(width - 250, y_position, width - 50, y_position)
    y_position -= 20

    # Totals
    c.setFont("Helvetica", 11)
    c.drawRightString(width - 200, y_position, "Subtotal:")
    c.drawRightString(width - 50, y_position, f"Rs{subtotal:,.2f}")
    y_position -= 20
    c.drawRightString(width - 200, y_position, f"Tax ({tax_rate_percent}%):")
    c.drawRightString(width - 50, y_position, f"Rs{tax_amount:,.2f}")
    y_position -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawRightString(width - 200, y_position, "Grand Total:")
    c.drawRightString(width - 50, y_position, f"Rs{grand_total:,.2f}")

    # Footer
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(50, 50, "Thank you for your business! Prices are valid for 30 days.")

    c.showPage()
    c.save()