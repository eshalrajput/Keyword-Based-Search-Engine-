document.addEventListener("DOMContentLoaded", function () {

    // Initialize: Log DOM load, set up flash message fade-outs.
    console.log("DOM loaded.");

    document.querySelectorAll(".flash-message").forEach(msg => {
        setTimeout(() => {
            msg.style.opacity = "0";
            setTimeout(() => msg.remove(), 500);
        }, 3000);
    });

    // Validate search form input.
    const searchForm = document.getElementById("search-form");
    if (searchForm) {
        searchForm.addEventListener("submit", event => {
            const queryInput = document.getElementById("search-query");
            if (queryInput.value.trim() === "") {
                alert("Please enter a search keyword!");
                event.preventDefault();
            }
        });
    }

    // Get DOM elements for search and suggestions.
    const searchBar = document.getElementById('search-bar');
    const suggestionsContainer = document.getElementById('suggestions-container');
    const suggestionsList = suggestionsContainer ? suggestionsContainer.querySelector('ul') : null;  // Safe access.
    const messageContainer = document.getElementById('message-container');

    let dictionary;
    let customDictionary = new Set();

    // Load and initialize the spell checking dictionary.
    fetch('https://unpkg.com/typo-js/dictionaries/en_US/en_US.aff')
        .then(response => response.arrayBuffer())
        .then(affBuffer => {
            fetch('https://unpkg.com/typo-js/dictionaries/en_US/en_US.dic')
                .then(response => response.arrayBuffer())
                .then(dicBuffer => {
                    dictionary = new Typo(affBuffer, dicBuffer);
                })
                .catch(error => showMessage(`Error loading dictionary: ${error}`, 'error'));
        })
        .catch(error => showMessage(`Error loading aff file: ${error}`, 'error'));

    // Display user messages.
    function showMessage(message, type = 'success') {
        if (messageContainer) {
            messageContainer.textContent = message;
            messageContainer.className = `alert alert-${type}`;
            messageContainer.style.display = 'block';
            if (type === 'success') {
                setTimeout(() => messageContainer.style.display = 'none', 3000);
            }
        }
    }

    // Display spelling suggestions.
    function showSuggestions(word, x, y) {
        if (!dictionary || !suggestionsContainer || !suggestionsList) return;

        const suggestions = dictionary.suggest(word);
        suggestionsList.innerHTML = '';

        if (suggestions.length === 0) {
            suggestionsContainer.style.display = 'none';
            return;
        }

        suggestions.forEach(suggestion => {
            const li = document.createElement('li');
            li.textContent = suggestion;
            li.addEventListener('click', () => {
                if (searchBar) {
                    searchBar.value = searchBar.value.replace(new RegExp(`\\b${word}\\b`, 'g'), suggestion);
                    searchBar.focus();
                }
                suggestionsContainer.style.display = 'none';
            });
            if (suggestionsList) suggestionsList.appendChild(li);
        });

        suggestionsContainer.style.top = `${y + (searchBar ? searchBar.offsetHeight : 0) + window.scrollY}px`;
        suggestionsContainer.style.left = `${x + (searchBar ? searchBar.offsetLeft : 0)}px`;
        suggestionsContainer.style.display = 'block';
    }

    // Handle real-time spell checking in search bar.
    if (searchBar) {
        searchBar.addEventListener('input', () => {
            const text = searchBar.value;
            const words = text.split(/\s+/);
            let newHTML = '';
            let lastIndex = 0;
            words.forEach(word => {
                const wordStartIndex = text.indexOf(word, lastIndex);
                const wordEndIndex = wordStartIndex + word.length;
                lastIndex = wordEndIndex;
                if (word === '') {
                    newHTML += ' ';
                    return;
                }
                newHTML += (!dictionary || !dictionary.check(word) && !customDictionary.has(word))
                    ? `<span class="misspelled">${word}</span>`
                    : word + ' ';
            });
            searchBar.innerHTML = newHTML;
        });
    }

    let customContextMenu = null;

    // Handle custom context menu for adding words.
    if (searchBar) {
        searchBar.addEventListener('contextmenu', event => {
            event.preventDefault();
            const selectedText = window.getSelection().toString().trim();

            if (selectedText) {
                if (customContextMenu) customContextMenu.remove();

                customContextMenu = document.createElement('div');
                customContextMenu.className = 'custom-context-menu';
                customContextMenu.style.left = `${event.clientX}px`;
                customContextMenu.style.top = `${event.clientY}px`;
                customContextMenu.style.position = 'absolute';
                customContextMenu.style.backgroundColor = '#f9f9f9';
                customContextMenu.style.border = '1px solid #ccc';
                customContextMenu.style.padding = '5px 0';
                customContextMenu.style.zIndex = '1000';

                const addToDictionaryOption = document.createElement('div');
                addToDictionaryOption.textContent = 'Add to dictionary';
                addToDictionaryOption.style.padding = '5px 15px';
                addToDictionaryOption.style.cursor = 'pointer';
                addToDictionaryOption.addEventListener('mouseover', () => addToDictionaryOption.style.backgroundColor = '#e0e0e0');
                addToDictionaryOption.addEventListener('mouseout', () => addToDictionaryOption.style.backgroundColor = '#f9f9f9');
                addToDictionaryOption.addEventListener('click', () => {
                    fetch('/add_to_dictionary', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `word=${encodeURIComponent(selectedText)}`,
                    })
                        .then(response => response.json())
                        .then(data => {
                            showMessage(data.message, data.success ? 'success' : 'error');
                            if (customContextMenu) {
                                customContextMenu.remove();
                                customContextMenu = null;
                            }
                        })
                        .catch(error => {
                            console.error('Error adding to dictionary:', error);
                            showMessage('An error occurred.', 'error');
                            if (customContextMenu) {
                                customContextMenu.remove();
                                customContextMenu = null;
                            }
                        });
                });

                customContextMenu.appendChild(addToDictionaryOption);
                document.body.appendChild(customContextMenu);

                document.addEventListener('click', function removeMenu(e) {
                    if (customContextMenu && !customContextMenu.contains(e.target) && e.target !== searchBar) {
                        customContextMenu.remove();
                        customContextMenu = null;
                        document.removeEventListener('click', removeMenu);
                    } else if (customContextMenu && customContextMenu.contains(e.target) && e.target === addToDictionaryOption) {
                        document.removeEventListener('click', removeMenu);
                    }
                });
            } else {
                 const text = searchBar.value;
                const words = text.split(/\s+/);
                let clickedWord = '';
                let lastIndex = 0;
                for (const word of words) {
                    const wordStartIndex = text.indexOf(word, lastIndex);
                    const wordEndIndex = wordStartIndex + word.length;
                    lastIndex = wordEndIndex;
                    if (event.clientX >= wordStartIndex && event.clientX <= wordEndIndex) {
                        clickedWord = word;
                        break;
                    }
                }
                if (clickedWord && dictionary && !dictionary.check(clickedWord) && !customDictionary.has(clickedWord)) {
                    showSuggestions(clickedWord, event.clientX, event.clientY);
                } else if (suggestionsContainer) {
                    suggestionsContainer.style.display = 'none';
                }
            }
        });
    }

    // Hide suggestions on click outside.
    document.addEventListener('click', event => {
        if (suggestionsContainer && !suggestionsContainer.contains(event.target) && event.target !== searchBar) {
            suggestionsContainer.style.display = 'none';
        }
    });

    // Add word to dictionary from suggestions.
    if (suggestionsContainer) {
        suggestionsContainer.addEventListener('contextmenu', event => {
            event.preventDefault();
            const target = event.target;
            if (target.tagName === 'LI') {
                const wordToAdd = target.textContent;
                fetch('/add_to_dictionary', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `word=${encodeURIComponent(wordToAdd)}`,
                })
                    .then(response => response.json())
                    .then(data => showMessage(data.message, data.success ? 'success' : 'error'))
                    .catch(error => {
                        console.error('Error adding to dictionary:', error);
                        showMessage('An error occurred.', 'error');
                    });
                suggestionsContainer.style.display = 'none';
                if (searchBar) searchBar.dispatchEvent(new Event('input'));
            }
        });
    }
});
