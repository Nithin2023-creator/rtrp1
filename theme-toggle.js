// Theme Toggle Script
const themeToggle = document.getElementById('theme-toggle');
const body = document.body;

// Apply the saved theme on page load
if (localStorage.getItem('theme') === 'dark') {
    body.classList.add('dark-mode');
    body.classList.remove('light-mode');
    if (themeToggle) {
        themeToggle.classList.add('bx-sun');
        themeToggle.classList.remove('bx-moon');
    }
} else {
    body.classList.add('light-mode');
    body.classList.remove('dark-mode');
    if (themeToggle) {
        themeToggle.classList.add('bx-moon');
        themeToggle.classList.remove('bx-sun');
    }
}

// Add event listener for theme toggle
if (themeToggle) {
    themeToggle.addEventListener('click', () => {
        body.classList.toggle('dark-mode');
        body.classList.toggle('light-mode');
        themeToggle.classList.toggle('bx-sun');
        themeToggle.classList.toggle('bx-moon');

        // Save the current theme in localStorage
        if (body.classList.contains('dark-mode')) {
            localStorage.setItem('theme', 'dark');
        } else {
            localStorage.setItem('theme', 'light');
        }
    });
}