
# Integrity Checker

Integrity Checker is a web application that allows users to upload files and calculate their integrity using MD5 hash algorithms. It can be used to verify the integrity and authenticity of files.

## Features

- Upload files for integrity checking.
- Check URL Reputation.
- Checking for malware of a single file and also for a directory on your pc.
- Used VIRUSTOTAL API.
- Built with Django and Python.

## Getting Started
To run this project locally, follow these steps:

1.Clone this repository:

      git clone https://github.com/somesh-jyothula/integrity-checker.git


2.Navigate to the project directory:
                  
      cd integrity-checker


3.Create a virtual environment (optional):

    python -m venv venv

  Activate the virtual environment:

  On Windows:

      venv\Scripts\activate

  On macOS and Linux:

    source venv/bin/activate


4.Apply database migrations:

    python manage.py migrate


5.Start the development server:

    python manage.py runserver


## Visit http://127.0.0.1:8000/ in your web browser to access the Integrity Checker.
## Note: Add your virustotal api key in views.py file.
