// static/js/security.js

document.addEventListener('DOMContentLoaded', function() {
    // ===== ФУНКЦИОНАЛЬНОСТЬ ДЛЯ ГЛАВНОЙ СТРАНИЦЫ =====
    const modal = document.getElementById('confirmModal');
    const confirmBtn = document.getElementById('confirmDelete');
    const cancelBtn = document.getElementById('cancelDelete');
    let deleteUrl = '';

    // Обработчики для ссылок удаления (если есть на странице)
    if (document.querySelectorAll('.delete-link').length > 0) {
        document.querySelectorAll('.delete-link').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                deleteUrl = this.href;
                if (modal) {
                    modal.style.display = 'block';
                }
            });
        });

        // Подтверждение удаления
        if (confirmBtn) {
            confirmBtn.addEventListener('click', function() {
                if (deleteUrl) {
                    window.location.href = deleteUrl;
                }
            });
        }

        // Отмена удаления
        if (cancelBtn) {
            cancelBtn.addEventListener('click', function() {
                if (modal) {
                    modal.style.display = 'none';
                }
                deleteUrl = '';
            });
        }

        // Закрытие модального окна при клике вне его
        if (modal) {
            window.addEventListener('click', function(e) {
                if (e.target === modal) {
                    modal.style.display = 'none';
                    deleteUrl = '';
                }
            });
        }
    }

    // ===== ВАЛИДАЦИЯ ФОРМЫ ДОБАВЛЕНИЯ ЗАМЕТКИ =====
    const addNoteForm = document.getElementById('addNoteForm');
    if (addNoteForm) {
        addNoteForm.addEventListener('submit', function(e) {
            const title = this.querySelector('input[name="title"]').value.trim();
            const content = this.querySelector('textarea[name="content"]').value.trim();

            if (!title || !content) {
                e.preventDefault();
                alert('Заполните все поля!');
                return false;
            }

            if (title.length > 100) {
                e.preventDefault();
                alert('Заголовок не должен превышать 100 символов!');
                return false;
            }
        });
    }

    // ===== ВАЛИДАЦИЯ ФОРМЫ РЕДАКТИРОВАНИЯ ЗАМЕТКИ =====
    const editNoteForm = document.getElementById('editNoteForm');
    if (editNoteForm) {
        editNoteForm.addEventListener('submit', function(e) {
            const title = document.getElementById('editTitle').value.trim();
            const content = document.getElementById('editContent').value.trim();

            if (!title || !content) {
                e.preventDefault();
                alert('Заполните все поля!');
                return false;
            }

            if (title.length > 100) {
                e.preventDefault();
                alert('Заголовок не должен превышать 100 символов!');
                return false;
            }

            // Дополнительная проверка: не изменились ли данные?
            const originalTitle = "{{ note.title|escapejs }}" || '';
            const originalContent = "{{ note.content|escapejs }}" || '';

            if (title === originalTitle && content === originalContent) {
                e.preventDefault();
                alert('Вы не внесли никаких изменений!');
                return false;
            }
        });
    }

    // ===== ПРЕДУПРЕЖДЕНИЕ ПРИ ПЕРЕЗАГРУЗКЕ С НЕСОХРАНЕННЫМИ ИЗМЕНЕНИЯМИ =====
    const editTitle = document.getElementById('editTitle');
    const editContent = document.getElementById('editContent');

    if (editTitle && editContent) {
        let originalData = {
            title: editTitle.value,
            content: editContent.value
        };

        let hasUnsavedChanges = false;

        // Отслеживаем изменения
        [editTitle, editContent].forEach(field => {
            field.addEventListener('input', function() {
                hasUnsavedChanges = true;
            });
        });

        // Предупреждение при уходе со страницы
        window.addEventListener('beforeunload', function(e) {
            if (hasUnsavedChanges) {
                e.preventDefault();
                e.returnValue = 'У вас есть несохраненные изменения. Вы уверены, что хотите уйти?';
                return e.returnValue;
            }
        });

        // Сбрасываем флаг при отправке формы
        if (editNoteForm) {
            editNoteForm.addEventListener('submit', function() {
                hasUnsavedChanges = false;
            });
        }
    }
});