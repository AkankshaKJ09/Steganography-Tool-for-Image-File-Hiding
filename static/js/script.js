document.addEventListener('DOMContentLoaded', function() {
    // Tab switching
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tab = button.dataset.tab;
            
            // Update active tab button
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            
            // Show active tab content
            tabContents.forEach(content => content.classList.remove('active'));
            document.getElementById(`${tab}-tab`).classList.add('active');
        });
    });
    
    // Toggle between text and file input
    const secretTypeRadios = document.querySelectorAll('input[name="secretType"]');
    const textInput = document.getElementById('textInput');
    const fileInput = document.getElementById('fileInput');
    
    secretTypeRadios.forEach(radio => {
        radio.addEventListener('change', () => {
            if (radio.value === 'text') {
                textInput.style.display = 'block';
                fileInput.style.display = 'none';
            } else {
                textInput.style.display = 'none';
                fileInput.style.display = 'block';
            }
        });
    });
    
    // Toggle password field for encryption
    const encryptionCheckbox = document.getElementById('encryption');
    const passwordGroup = document.getElementById('passwordGroup');
    
    encryptionCheckbox.addEventListener('change', () => {
        passwordGroup.style.display = encryptionCheckbox.checked ? 'block' : 'none';
    });
    
    // Toggle password field for decryption
    const decryptionCheckbox = document.getElementById('decryption');
    const decryptPasswordGroup = document.getElementById('decryptPasswordGroup');
    
    decryptionCheckbox.addEventListener('change', () => {
        decryptPasswordGroup.style.display = decryptionCheckbox.checked ? 'block' : 'none';
    });
    
    // Image preview for cover image
    const coverImageInput = document.getElementById('coverImage');
    const coverPreview = document.getElementById('coverPreview');
    
    coverImageInput.addEventListener('change', function() {
        if (this.files && this.files[0]) {
            const reader = new FileReader();
            
            reader.onload = function(e) {
                coverPreview.innerHTML = `<img src="${e.target.result}" alt="Cover Preview">`;
            }
            
            reader.readAsDataURL(this.files[0]);
        }
    });
    
    // Image preview for stego image
    const stegoImageInput = document.getElementById('stegoImage');
    const stegoPreview = document.getElementById('stegoPreview');
    
    stegoImageInput.addEventListener('change', function() {
        if (this.files && this.files[0]) {
            const reader = new FileReader();
            
            reader.onload = function(e) {
                stegoPreview.innerHTML = `<img src="${e.target.result}" alt="Stego Preview">`;
            }
            
            reader.readAsDataURL(this.files[0]);
        }
    });
    
    // Encode data
    const encodeBtn = document.getElementById('encodeBtn');
    const encodeResult = document.getElementById('encodeResult');
    
    encodeBtn.addEventListener('click', async function() {
        // Validate form
        const coverImage = document.getElementById('coverImage').files[0];
        if (!coverImage) {
            showError(encodeResult, 'Please select a cover image');
            return;
        }
        
        const secretType = document.querySelector('input[name="secretType"]:checked').value;
        let secretData = '';
        
        if (secretType === 'text') {
            secretData = document.getElementById('secretText').value;
            if (!secretData) {
                showError(encodeResult, 'Please enter some text to encode');
                return;
            }
        } else {
            const secretFile = document.getElementById('secretFile').files[0];
            if (!secretFile) {
                showError(encodeResult, 'Please select a file to encode');
                return;
            }
        }
        
        const useEncryption = document.getElementById('encryption').checked;
        const password = document.getElementById('password').value;
        
        if (useEncryption && !password) {
            showError(encodeResult, 'Please enter an encryption password');
            return;
        }
        
        // Create form data
        const formData = new FormData();
        formData.append('coverImage', coverImage);
        formData.append('secretType', secretType);
        
        if (secretType === 'text') {
            formData.append('secretText', secretData);
        } else {
            const secretFile = document.getElementById('secretFile').files[0];
            formData.append('secretFile', secretFile);
        }
        
        if (useEncryption) {
            formData.append('encryption', 'true');
            formData.append('password', password);
        }
        
        // Show loading state
        encodeBtn.disabled = true;
        encodeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Encoding...';
        
        try {
            // Send request to server
            const response = await fetch('/encode', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                encodeResult.innerHTML = `
                    <div class="success">
                        <p><i class="fas fa-check-circle"></i> Data encoded successfully!</p>
                        <div class="image-preview">
                            <img src="${result.image}" alt="Encoded Image">
                        </div>
                        <a href="${result.image}" download="${result.filename}" class="download-btn">
                            <i class="fas fa-download"></i> Download Image
                        </a>
                    </div>
                `;
            } else {
                showError(encodeResult, result.error);
            }
        } catch (error) {
            showError(encodeResult, 'An error occurred: ' + error.message);
        } finally {
            // Reset button state
            encodeBtn.disabled = false;
            encodeBtn.innerHTML = '<i class="fas fa-shield-alt"></i> Encode Data';
        }
    });
    
    // Decode data
    const decodeBtn = document.getElementById('decodeBtn');
    const decodeResult = document.getElementById('decodeResult');
    
    decodeBtn.addEventListener('click', async function() {
        // Validate form
        const stegoImage = document.getElementById('stegoImage').files[0];
        if (!stegoImage) {
            showError(decodeResult, 'Please select a stego image');
            return;
        }
        
        const useDecryption = document.getElementById('decryption').checked;
        const password = document.getElementById('decryptPassword').value;
        
        if (useDecryption && !password) {
            showError(decodeResult, 'Please enter a decryption password');
            return;
        }
        
        // Create form data
        const formData = newFormData();
        formData.append('stegoImage', stegoImage);
        
        if (useDecryption) {
            formData.append('decryption', 'true');
            formData.append('decryptPassword', password);
        }
        
        // Show loading state
        decodeBtn.disabled = true;
        decodeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Decoding...';
        
        try {
            // Send request to server
            const response = await fetch('/decode', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                let html = `
                    <div class="success">
                        <p><i class="fas fa-check-circle"></i> Data decoded successfully!</p>
                        <p>${result.message}</p>
                `;
                
                if (result.file) {
                    html += `
                        <a href="${result.file_url}" class="download-btn">
                            <i class="fas fa-download"></i> Download ${result.file}
                        </a>
                    `;
                }
                
                html += `</div>`;
                decodeResult.innerHTML = html;
            } else {
                showError(decodeResult, result.error);
            }
        } catch (error) {
            showError(decodeResult, 'An error occurred: ' + error.message);
        } finally {
            // Reset button state
            decodeBtn.disabled = false;
            decodeBtn.innerHTML = '<i class="fas fa-search"></i> Decode Data';
        }
    });
    
    // Helper function to show errors
    function showError(element, message) {
        element.innerHTML = `
            <div class="error">
                <p><i class="fas fa-exclamation-circle"></i> ${message}</p>
            </div>
        `;
    }
});
