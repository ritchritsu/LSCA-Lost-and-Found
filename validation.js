// Login Form Validation
const loginForm = document.getElementById("loginForm"),
      emailInput = loginForm?.querySelector(".email"),
      passwordInput = loginForm?.querySelector(".password"),
      emailError = loginForm?.querySelector(".email-error"),
      passwordError = loginForm?.querySelector(".password-error");

if (loginForm) {
    loginForm.addEventListener("submit", (e) => {
        if (!validateEmail(emailInput, emailError) || !validatePassword(passwordInput, passwordError)) {
            e.preventDefault(); // Prevent form submission if validation fails
        }
    });

    emailInput?.addEventListener("keyup", () => validateEmail(emailInput, emailError));
    passwordInput?.addEventListener("keyup", () => validatePassword(passwordInput, passwordError));
}

// Register Form Validation
const registerForm = document.getElementById("registerForm"),
      confirmInput = registerForm?.querySelector(".confirmation"),
      confirmError = registerForm?.querySelector(".confirmation-error");

if (registerForm) {
    registerForm.addEventListener("submit", (e) => {
        if (!validateEmail(emailInput, emailError) || !validatePassword(passwordInput, passwordError) || !validateConfirmation(passwordInput, confirmInput, confirmError)) {
            e.preventDefault(); // Prevent form submission if validation fails
        }
    });

    emailInput?.addEventListener("keyup", () => validateEmail(emailInput, emailError));
    passwordInput?.addEventListener("keyup", () => validatePassword(passwordInput, passwordError));
    confirmInput?.addEventListener("keyup", () => validateConfirmation(passwordInput, confirmInput, confirmError));
}

// Validation Functions
function validateEmail(input, error) {
    const emailPattern = /^[^ ]+@[^ ]+\.[a-z]{2,3}$/;
    if (!input.value.match(emailPattern)) {
        error.style.display = 'block';
        return false;
    }
    error.style.display = 'none';
    return true;
}

function validatePassword(input, error) {
    const passwordPattern = /^(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    if (!input.value.match(passwordPattern)) {
        error.style.display = 'block';
        return false;
    }
    error.style.display = 'none';
    return true;
}

function validateConfirmation(passwordInput, confirmInput, error) {
    if (passwordInput.value !== confirmInput.value) {
        error.style.display = 'block';
        return false;
    }
    error.style.display = 'none';
    return true;
}
