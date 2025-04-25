document.addEventListener('DOMContentLoaded', () => {
    // Seleccionar todo checkbox
    const selectAllCheckbox = document.getElementById('select-all-checkbox');
    const rowCheckboxes = document.querySelectorAll('.row-checkbox');

    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', () => {
            rowCheckboxes.forEach(checkbox => {
                checkbox.checked = selectAllCheckbox.checked;
            });
            updateSelectAllState();
        });
    }

    rowCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', () => {
            updateSelectAllState();
        });
    });

    function updateSelectAllState() {
        if (rowCheckboxes.length > 0) {
            selectAllCheckbox.checked = Array.from(rowCheckboxes).every(cb => cb.checked);
        }
    }

    // Manejo de notificaciones
    const notification = document.getElementById('notification');
    if (notification) {
        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 3000);
    }
});