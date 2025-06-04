// Email check function with error handling
async function checkEmail(email) {
    try {
        // First try the POST endpoint
        const postResponse = await fetch('http://localhost:4009/api/check-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ email })
        });

        if (!postResponse.ok) {
            throw new Error(`HTTP error! status: ${postResponse.status}`);
        }

        const data = await postResponse.json();
        return data;
    } catch (postError) {
        console.log('POST request failed, trying GET...', postError);
        
        // If POST fails, try the GET endpoint
        try {
            const getResponse = await fetch(`http://localhost:4009/api/check-email/${encodeURIComponent(email)}`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (!getResponse.ok) {
                throw new Error(`HTTP error! status: ${getResponse.status}`);
            }

            const data = await getResponse.json();
            return data;
        } catch (getError) {
            console.error('Both POST and GET requests failed:', getError);
            throw new Error('Failed to check email. Please try again later.');
        }
    }
}

// Example usage in your form submission
document.querySelector('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.querySelector('input[type="email"]').value;
    
    try {
        const result = await checkEmail(email);
        if (result.exists) {
            // Handle existing email
            console.log('Email exists');
        } else {
            // Handle non-existing email
            console.log('Email does not exist');
        }
    } catch (error) {
        console.error('Error checking email:', error);
        // Handle error appropriately in your UI
    }
}); 