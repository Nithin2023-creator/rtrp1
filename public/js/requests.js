// Configure the base URL based on environment
const BASE_URL = window.location.hostname === 'localhost' 
    ? 'http://localhost:4009'
    : 'https://rtrp1.vercel.app';

// Email check function with error handling
async function checkEmail(email) {
    try {
        // First try the POST endpoint
        const postResponse = await fetch(`${BASE_URL}/api/check-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ email }),
            mode: 'cors',
            credentials: 'include'
        });

        if (!postResponse.ok) {
            throw new Error(`HTTP error! status: ${postResponse.status}`);
        }

        const data = await postResponse.json();
        return data;
    } catch (postError) {
        console.log('POST request failed, trying GET...', postError);
        
        // If POST fails, try the GET endpoint with different approach
        try {
            const getResponse = await fetch(`${BASE_URL}/api/check-email/${encodeURIComponent(email)}`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                mode: 'cors',
                credentials: 'include'
            });

            if (!getResponse.ok) {
                throw new Error(`HTTP error! status: ${getResponse.status}`);
            }

            const data = await getResponse.json();
            return data;
        } catch (getError) {
            console.error('Both POST and GET requests failed:', getError);
            // Try alternative approach without credentials
            try {
                const response = await fetch(`${BASE_URL}/api/check-email/${encodeURIComponent(email)}`, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    mode: 'cors'
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                const data = await response.json();
                return data;
            } catch (finalError) {
                console.error('All attempts failed:', finalError);
                throw new Error('Failed to check email. Please try again later.');
            }
        }
    }
}

// Example usage in your form submission
document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('form');
    const errorDiv = document.createElement('div');
    errorDiv.id = 'emailCheckError';
    errorDiv.style.color = 'red';
    errorDiv.style.display = 'none';
    form.appendChild(errorDiv);

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.querySelector('input[type="email"]').value;
        errorDiv.style.display = 'none';
        
        try {
            const result = await checkEmail(email);
            if (result.exists) {
                // Handle existing email
                console.log('Email exists');
                errorDiv.textContent = 'Email already exists';
                errorDiv.style.color = 'red';
                errorDiv.style.display = 'block';
            } else {
                // Handle non-existing email
                console.log('Email does not exist');
                errorDiv.textContent = 'Email is available';
                errorDiv.style.color = 'green';
                errorDiv.style.display = 'block';
            }
        } catch (error) {
            console.error('Error checking email:', error);
            errorDiv.textContent = 'Error checking email. Please try again.';
            errorDiv.style.display = 'block';
        }
    });
}); 