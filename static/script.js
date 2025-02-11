function showToast(message, type = 'success') {
    const colors = {
        success: '#087830',
        error: '#dc3545',
        warning: '#ffc107',
        info: '#0dcaf0'
    };

    Toastify({
        text: message,
        duration: 3000,
        gravity: "top",
        position: "right",
        style: {
            background: colors[type],
            borderRadius: "8px",
            boxShadow: "0 3px 6px rgba(0,0,0,0.16)",
        },
    }).showToast();
}