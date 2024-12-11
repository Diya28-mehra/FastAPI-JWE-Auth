##FastAPI JWE Authentication 🔐

Welcome to the FastAPI JWE Authentication project!
This project demonstrates how to implement JSON Web Encryption (JWE) with FastAPI to securely handle user authentication in a web application. It includes user registration, login, and token-based authentication, with a focus on encryption for added security.


Features 🌟

User Registration: Secure user sign-up with password hashing and email validation.

User Login: Log in with email and password to receive a secure encrypted JWT (JWE).

Token-Based Authentication: Authenticate API requests using JWE tokens to ensure data privacy.

FastAPI: Built with the powerful FastAPI framework, providing high performance and automatic documentation.

Secure Encryption: Use of JWE to protect sensitive user data in tokens.

Swagger UI: Auto-generated interactive API documentation powered by FastAPI.


Technologies Used 🛠️

FastAPI: A modern, fast web framework for building APIs with Python.

Python: The core programming language used in this project.

PyJWT: A library used to work with JWT tokens.

Cryptography: Used to handle JWE encryption and decryption.

SQLite: Database for storing user data (can be swapped for other databases).

Uvicorn: ASGI server to run the FastAPI app.

Pydantic: Data validation and settings management for FastAPI.


Installation Guide ⚙️
To set up the project locally, follow the steps below:

1. Clone the repository
git clone https://github.com/Diya28-mehra/FastAPI-JWE-Auth.git

2. Navigate to the project directory
cd FastAPI-JWE-Auth

3. Create a virtual environment (Optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`

4. Install dependencies
pip install -r requirements.txt

5. Run the application
uvicorn main:app --reload

6. Access API documentation
http://127.0.0.1:8000/docs

You can test the user registration, login, and other endpoints directly from the UI.


API Endpoints 📡
Here are the key API endpoints for this project:

POST /register: Register a new user with email and password.
POST /login: Login with credentials and receive a JWE token.
GET /secure-endpoint: A protected endpoint requiring a valid JWE token.

Contact ✉️
If you have any questions or suggestions, feel free to reach out:

Email: itsdiyamehra@example.com
GitHub: Diya28-mehra
