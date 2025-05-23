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
      source env/bin/activate
      ```

3. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

## Running the Application Locally

1. Make a copy of the `.env.sample` file and rename that copy to `.env`. Update the values in the `.env` file as needed.

2. Look through the `.env` file and make sure USE_LOCAL_CONFIG is set to `1` to use the local configuration.

3. Navigate to `wsgi` and run the application:

    ```bash
    python -m wsgi
    ```

4. The application will now be available at `http://127.0.0.1:5000/`, and `http://192.168.1.72:5000/` if you are using the local configuration.

You can find the documentation for the API at `http://127.0.0.1:5000/docs` on the local config or alternatively at `http://networkninjas.gobbler.info/docs`
