document.addEventListener('DOMContentLoaded', () => {
    console.log("App loaded!");

    // Обработка формы регистрации
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', async (event) => {
            event.preventDefault(); // Предотвращаем стандартное поведение формы
            console.log("Register form submitted!");

            const name = document.getElementById('register-name').value;
            const email = document.getElementById('register-email').value;
            const password = document.getElementById('register-password').value;

            try {
                const response = await fetch('/api-register/', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, email, password })
                });

                if (response.ok) {
                    const data = await response.json();
                    alert("Registration successful! ");
                    window.location.href = '/login/'; // Перенаправляем на страницу входа
                } else {
                    const error = await response.json();
                    alert("Error: " + error.message);
                }
            } catch (err) {
                console.error("Error during registration:", err);
                alert("An unexpected error occurred. Please try again.");
            }
        });
    }

    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            console.log("Login form submitted!");

            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;

            try {
                const response = await fetch('/api-login/', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });

                if (response.ok) {
                    const data = await response.json();
                    alert("Login successful! ");
                    localStorage.setItem("auth_token", data.access_token);  // Сохраняем токен в localStorage
                    window.location.href = '/listings/';
                }
                else {
                    const error = await response.json();
                    alert("Error: " + error.message);
                }
            } catch (err) {
                console.error("Error during login:", err);
                alert("An unexpected error occurred. Please try again.");
            }
        });
    }

    async function loadListings() {
        try {
            const token = localStorage.getItem("auth_token");

            if (!token) {
                alert("You must be logged in to view listings!");
                return;
            }
            const response = await fetch(`/all-listings/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`  // Добавляем токен в заголовок
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const text = await response.text(); // Читаем ответ как текст
            console.log("Server response:", text); // Логируем ответ для дебага

            let data;
            try {
                data = JSON.parse(text);
            } catch (e) {
                throw new Error("Failed to parse JSON: " + e.message);
            }

            if (Array.isArray(data.listings)) {
                const listings = data.listings;

                // Очищаем контейнер перед добавлением новых элементов
                const container = document.getElementById('listing-container');
                container.innerHTML = '';

                // Добавляем элементы на страницу
                listings.forEach(listing => {
                    const listingElement = document.createElement('div');
                    listingElement.classList.add('listing');
                    listingElement.innerHTML = `
                        <h3><a href="/listing-management/${listing.listingid}/">${listing.address}</a></h3>
                        <p><strong>Price:</strong> $${listing.price}</p>
                        <p><strong>Area:</strong> ${listing.area} m²</p>
                        <p><strong>Status:</strong> ${listing.status}</p>
                    `;
                    container.appendChild(listingElement);
                });
            } else {
                throw new Error("Expected an array of listings, but received: " + typeof data.listings);
            }
        } catch (error) {
            console.error('Error loading listings:', error);
        }
    }

    loadListings();


    // Обработчики событий для кнопок
    const logoutButton = document.getElementById("logout");
    const createListingButton = document.getElementById("create-listing");
    const confirmButton = document.getElementById("confirm-logout");
    const cancelButton = document.getElementById("cancel-logout");
    const form = document.getElementById("create-listing-form");

    if (logoutButton) {
        logoutButton.addEventListener("click", () => {
            window.location.href = "/logout-confirm/";
        });
    }

    if (createListingButton) {
        createListingButton.addEventListener("click", () => {
            window.location.href = "/listings-create/";
        });
    }

    // Обработка формы создания объявления
    if (form) {
        form.addEventListener("submit", async (e) => {
            e.preventDefault(); // Предотвращаем перезагрузку страницы

            const formData = new FormData(form);
            const listingData = Object.fromEntries(formData.entries()); // Преобразование FormData в объект

            try {
                const response = await fetch("/create-listings/", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${localStorage.getItem("auth_token")}`,
                    },
                    body: JSON.stringify(listingData),
                });

                if (response.ok) {
                    const result = await response.json();
                    document.getElementById("response-message").innerText = 
                        `Listing created successfully: ID ${result.listingid}`;
                    form.reset();
                    window.location.href = "/listings/";
                } else {
                    const error = await response.json();
                    document.getElementById("response-message").innerText = 
                        `Error: ${error.message || "Something went wrong"}`;
                }
            } catch (error) {
                document.getElementById("response-message").innerText = 
                    `Network error: ${error.message}`;
            }
        });
    }

    if (confirmButton) {
        confirmButton.addEventListener("click", async () => {
            const token = localStorage.getItem("auth_token");

            if (!token) {
                alert("You are not logged in.");
                window.location.href = "/login/";
                return;
            }

            try {
                const response = await fetch("/api-logout/", {
                    method: "POST",
                    headers: {
                        "Authorization": `Bearer ${token}`,
                        "Content-Type": "application/json",
                    },
                });

                if (response.ok) {
                    alert("You have been logged out.");
                    localStorage.removeItem("auth_token");
                    window.location.href = "/login/";
                } else {
                    const data = await response.json();
                    alert(data.detail || "Error logging out.");
                }
            } catch (error) {
                console.error("Error during logout:", error);
                alert("An error occurred. Please try again later.");
            }
        });
    }

    if (cancelButton) {
        cancelButton.addEventListener("click", () => {
            window.location.href = "/listings/";
        });
    }

});
