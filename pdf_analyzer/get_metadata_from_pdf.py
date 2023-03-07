import sys

from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument

pdf_file = sys.argv[1]
print(pdf_file)

fp = open(pdf_file, 'rb')
parser = PDFParser(fp)
doc = PDFDocument(parser)

print(doc.info)  # The "Info" metadata
