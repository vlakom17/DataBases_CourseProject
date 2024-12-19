from app import create_app

# Создание экземпляра приложения
app = create_app()

# Запуск приложения
if __name__ == "__main__":
    app.run(debug=True)