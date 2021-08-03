from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate
from reportlab.lib.pagesizes import letter
from reportlab.platypus import Table, TableStyle, figures, Paragraph, Spacer
from reportlab.lib import colors
import pandas as pd
from PyPDF2 import PdfFileReader, PdfFileWriter
from reportlab.lib.units import inch
import os

def generate_pie(csvdf):
    csvdf.AlertName.apply(str)
    a = csvdf.groupby(["ResultStatus"]).count()
    plot = a.plot.pie(y="AlertName", figsize=(5, 6), autopct='%1.1f%%', shadow=True).get_figure()
    plot.savefig("a.jpg")
    
def generate_report(csvf, outputf, infof, logger):
    logger.info("Generating PDF Report...")

    csv_dat = [['Deployment Type', 'Success Count', 'Fail Count']]
    with open(infof, 'r') as csv:
        for x in csv:
            x = x.replace('\n', '').replace('\"', '').split(',')
            csv_dat.append(x)
        csv.close()
    infotable = Table(csv_dat, rowHeights = [.37*inch] * len(csv_dat))

    all_data = [['AlertName', 'Result', 'Ability']]
    with open(csvf, 'r') as csv:
        for x in csv:
            tam = len(x)
            x = x.replace('\n', '').replace('\"', '').split(',')
            if tam > 120:
                pos = x[0][:64].rfind(' ')
                x[0] = '\n'.join([x[0][:pos], x[0][pos+1:]])
            del[x[1]]
            all_data.append(x)
        csv.close()
    result_csv = pd.read_csv(csvf, index_col=False, names=['AlertName', 'Timestamp', 'ResultStatus', 'Ability'])
    dt = result_csv.drop('Timestamp', axis=1)
    Pdf = SimpleDocTemplate(
        filename='file.pdf',
        pagesize=letter
    )
    table = Table(all_data, rowHeights = [.37*inch] * len(all_data))
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkcyan),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('LINEABOVE', (0, 1), (2, -1), 2, colors.black),
        ('LINEBEFORE', (0, 1), (2, -1), 2, colors.black),
        ('BOX', (0, 0), (-1, -1), 2, colors.black),
        ('ALIGNMENT', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE')
    ])
    
    table.setStyle(style)
    infotable.setStyle(style)
    
    ell = list()
    paragraph_1 = Paragraph("Automata - Detection Validation Report", getSampleStyleSheet()['Title'])
    ell.append(paragraph_1)
    ell.append(Spacer(1, inch * 0.5))
    ell.append(infotable)
    ell.append(Spacer(1, inch * 0.5))
    ell.append(table)
    Pdf.build(ell)
    Graph = SimpleDocTemplate(
        filename='graph.pdf',
        pagesize=letter
    )
    all = list()
    paragraph = ParagraphStyle('', aligment=10)
    generate_pie(dt)
    paragraph_1 = Paragraph("Result Percentage", ParagraphStyle('kk', fontSize=18, alignment=1), )
    all.append(paragraph_1)
    all.append(figures.ImageFigure("a.jpg", caption=''))
    Graph.build(all)
    tabf = open('file.pdf', 'rb')
    tab = PdfFileReader(tabf)
    graphf = open('graph.pdf', 'rb')
    graph = PdfFileReader(graphf)
    new_file = open(outputf, 'wb')
    output = PdfFileWriter()
    for x in range(0, tab.numPages):
        output.addPage(tab.getPage(x))
    output.addPage(graph.getPage(0))
    output.write(new_file)
    new_file.close()
    logger.info("PDF Report generated: " + outputf)
    tabf.close()
    graphf.close()
    os.remove("file.pdf")
    os.remove("graph.pdf")