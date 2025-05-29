# CloudWorx-Backend

Flask-Based Backend for CloudWorx project.

As part of a joint project called "CloudWorx", this repository is part of a three part series involving the work of three students.
The other two repositories are:

- [CloudWorx-Client led by @Elle0-0](https://github.com/Elle0-0/CloudWorx-Desktop-Client)
- [CloudWorx-Web led by @darragh0](https://github.com/darragh0/CloudWorx-WApp)

![CloudWorx Logo](cloudworx-logo.png)

## Virtual Environment Setup

1. Create a virtual environment:

    ```bash
    python -m venv venv
    ```

2. Activate the virtual environment:
    - On Windows:

      ```bash
      .\venv\Scripts\activate
      ```

    - On macOS/Linux:

      ```bash
      source venv/bin/activate
      ```

3. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

## Running the Application Locally

1. Make a copy of the `.env.sample` file and rename that copy to `.env`. Update the values in the `.env` file as needed.

2. Look through the `.env` file and make sure USE_LOCAL_CONFIG is set to `1` to use the local configuration.

3. For secure TCP connections, generate TLS certificates or provide your own:

    ```bash
    # Generate self-signed certificates for testing
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
    ```

    You can also run:

    ```bash
    python utils/generate_cert.py --common-name cloudworx.local --output-dir .
    ```

   For production, use properly issued certificates from a trusted CA.

4. Navigate to `wsgi` and run the application:

    ```bash
    python -m wsgi
    ```

5. The application will now be available at `http://127.0.0.1:5000/` for HTTP API access, and `http://0.0.0.0:6174` for secure TCP connections.

You can find the documentation for the API at `http://127.0.0.1:5000/docs` on the local config or alternatively at `http://networkninjas.gobbler.info/docs`
