from app import create_app

app = create_app()

if "tcp_server" in app.extensions:
    app.extensions["tcp_server"].start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6175, debug=True)  # noqa: S104
