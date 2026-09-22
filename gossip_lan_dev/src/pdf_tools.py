import os
from io import BytesIO
import PyPDF2

# get data of pdf with all metadata removed
def get_pdf_data_clean(file_path: str) -> tuple[str, str]:
    # get out of the /src working directory
    file_path = '../' + file_path

    # check path exists
    if os.path.exists(file_path):
        # open pdf as a binary file
        with open(file_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            writer = PyPDF2.PdfWriter()
            
            # copy pages without metadata
            for page in reader.pages:
                writer.add_page(page)
                
            # write to a bytes buffer
            buffer = BytesIO()
            writer.write(buffer)
            buffer.seek(0)

        # get bytes and their hash
        data = buffer.read()
        hashed = hashlib.sha256(data).hexdigest()
        return data, hashed
    else:
        # file doesn't exist
        return '', ''
