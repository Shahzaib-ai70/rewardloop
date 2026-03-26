// Toast Notification System
function showToast(message, type = 'success') {
    // Create container if it doesn't exist
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    // Icon based on type
    let iconClass = 'fa-check-circle';
    if (type === 'error') iconClass = 'fa-times-circle';
    if (type === 'warning') iconClass = 'fa-exclamation-triangle';
    if (type === 'info') iconClass = 'fa-info-circle';

    toast.innerHTML = `
        <i class="fas ${iconClass} toast-icon"></i>
        <span class="toast-message">${message}</span>
        <i class="fas fa-times toast-close" onclick="this.parentElement.remove()"></i>
    `;

    container.appendChild(toast);

    // Auto remove after 3 seconds
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease forwards';
        setTimeout(() => {
            if (toast.parentElement) toast.remove();
        }, 300);
    }, 3000);
}

// Custom Confirm Modal
function showConfirm(title, message, callback, confirmText = 'Yes, Confirm', cancelText = 'Cancel', isDanger = false) {
    // Remove existing modal if any
    const existing = document.querySelector('.custom-confirm-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.className = 'custom-confirm-overlay';

    const btnClass = isDanger ? 'btn-confirm-danger' : 'btn-confirm-ok';
    const iconClass = isDanger ? 'fa-exclamation-triangle' : 'fa-question-circle';
    const iconColor = isDanger ? '#d63031' : '#f1c40f';

    overlay.innerHTML = `
        <div class="custom-confirm-box">
            <i class="fas ${iconClass} confirm-icon" style="color: ${iconColor}"></i>
            <h3 class="confirm-title">${title}</h3>
            <p class="confirm-message">${message}</p>
            <div class="confirm-actions">
                <button class="btn-confirm-cancel" id="confirmCancel">${cancelText}</button>
                <button class="${btnClass}" id="confirmOk">${confirmText}</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    // Event Listeners
    document.getElementById('confirmCancel').addEventListener('click', () => {
        overlay.remove();
    });

    document.getElementById('confirmOk').addEventListener('click', () => {
        overlay.remove();
        if (callback) callback();
    });

    // Close on background click
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) overlay.remove();
    });
}
