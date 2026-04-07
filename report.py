from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf(results, filename="report.pdf"):
    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("PhantomSurface Security Report", styles["Title"]))
    elements.append(Spacer(1, 10))

    for res in results:
        elements.append(Paragraph(f"Domain: {res['domain']}", styles["Heading2"]))
        elements.append(Paragraph(f"Risk: {res['risk']}", styles["Normal"]))
        elements.append(Paragraph(f"Summary: {res['summary']}", styles["Normal"]))

        elements.append(Paragraph(f"Ports: {res['ports']}", styles["Normal"]))
        elements.append(Paragraph(f"Technologies: {res['technologies']}", styles["Normal"]))

        elements.append(Spacer(1, 15))

    doc.build(elements)
    return filename
