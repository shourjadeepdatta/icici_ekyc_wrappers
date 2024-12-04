import PyPDF2

# Open the files that have to be merged one by one
with open('ICICI_93281518.pdf', 'rb') as file1, open('ICICI_93281518_cams.pdf', 'rb') as file2:
    reader1 = PyPDF2.PdfReader(file1)
    reader2 = PyPDF2.PdfReader(file2)

    # Create a new PdfWriter object which represents a blank PDF document
    writer = PyPDF2.PdfWriter()

    # Loop through all the pages of the first document and add them
    for pageNum in range(len(reader1.pages)):
        page = reader1.pages[pageNum]
        writer.add_page(page)

    # Loop through all the pages of the second document and add them
    for pageNum in range(len(reader2.pages)):
        page = reader2.pages[pageNum]
        writer.add_page(page)

    # Write out the merged PDF
    with open('merged.pdf', 'wb') as output_pdf:
        writer.write(output_pdf)
