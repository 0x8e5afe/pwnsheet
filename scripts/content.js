let phaseTextIndex = {};

async function loadMarkdownFiles() {
    const mdFiles = [
        '01 - Reconnaissance & Enumeration.md',
        '02 - Vulnerability Research & Exploitation.md',
        '03 - Post Exploitation & Privilege Escalation.md',
        '04 - Lateral Movement.md',
        '05 - Active Directory Exploitation.md',
    ];

    const phaseList = document.getElementById('phaseList');
    phaseList.innerHTML = '';

    let loadedCount = 0;
    const discoveredParams = new Set();

    for (let i = 0; i < mdFiles.length; i++) {
        const filename = "notes/"+mdFiles[i];
        
        try {
            const response = await fetch(filename);
            if (response.ok) {
                const content = await response.text();
                phases[filename] = content;
                phaseTextIndex[filename] = extractPlainTextFromMarkdown(content);
                loadedCount++;
                collectParametersFromContent(content, discoveredParams);
                
                const btn = document.createElement('button');
                btn.className = 'phase-btn';
                if (i === 0) {
                    btn.classList.add('active');
                    currentPhase = filename;
                }
                btn.dataset.phase = filename;
                btn.textContent = filename.replace('notes/','').replace('.md', '');
                btn.setAttribute('aria-label', `Load phase: ${filename.replace('.md', '')}`);
                
                btn.addEventListener('click', (e) => {
                    document.querySelectorAll('.phase-btn').forEach(b => b.classList.remove('active'));
                    e.target.classList.add('active');
                    currentPhase = e.target.dataset.phase;
                    checkboxStates.clear();
                    loadPhase(currentPhase);
                });
                
                phaseList.appendChild(btn);
            }
        } catch (error) {
            console.error(`Error loading ${filename}:`, error);
        }
    }

    if (loadedCount === 0) {
        phaseList.innerHTML = '<div class="loading-text">⚠️ No markdown files found.</div>';
        return;
    }

    allDiscoveredParameters = Array.from(discoveredParams).sort();
    hydrateParametersFromStorage();
    renderParametersPanel();

    if (currentPhase && phases[currentPhase]) {
        loadPhase(currentPhase);
    } else if (Object.keys(phases).length > 0) {
        currentPhase = Object.keys(phases)[0];
        loadPhase(currentPhase);
    }

    maybeShowInitialParamsModal();
}

function loadPhase(phase) {
    const content = phases[phase] || '';
    currentContent = content;
    checkboxStates.clear();
    clearCodeBlockSelection(true);
    paramSearchTerm = '';

    if (!Object.keys(parameters).length && allDiscoveredParameters.length) {
        hydrateParametersFromStorage();
    }

    const matches = content.matchAll(/\[([ xX])\]/g);
    let index = 0;
    for (const match of matches) {
        checkboxStates.set(index, match[1].toLowerCase() === 'x');
        index++;
    }

    const storedStates = loadCheckboxStatesFromStorage(phase);
    if (storedStates) {
        storedStates.forEach((state, idx) => {
            if (typeof state === 'boolean') {
                checkboxStates.set(idx, state);
            }
        });
    }

    renderParametersPanel();
    renderContent();
    resetContentScroll();
    maybeShowInitialParamsModal();
}

function renderContent() {
    codeBlockParamMap = extractCodeBlockParameters(currentContent);
    const contentWithValues = applyParametersToContent(currentContent);
    const html = marked.parse(contentWithValues);
    document.getElementById('contentArea').innerHTML = html;
    
    enhanceCodeBlocks();
    highlightHashComments();
    highlightParametersInText();
    highlightParametersInCodeBlocks();
    
    makeCheckboxesInteractive();
    setupCodeBlockSelection();
}

function applyParametersToContent(content) {
    let processedContent = content;

    Object.keys(parameters).forEach(param => {
        const value = wrapValueWithMarkers(param, getDisplayValueForParam(param));
        const safeParam = param.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&');
        const regex1 = new RegExp(`<${safeParam}>`, 'g');
        const regex2 = new RegExp(`{{${safeParam}}}`, 'g');
        processedContent = processedContent.replace(regex1, () => value);
        processedContent = processedContent.replace(regex2, () => value);
    });

    return processedContent;
}

function wrapValueWithMarkers(param, value) {
    return `${PARAM_MARKER_START}${param}${PARAM_SEPARATOR}${value}${PARAM_MARKER_END}`;
}

function extractCodeBlockParameters(content) {
    try {
        const tokens = marked.lexer(content);
        return tokens
            .filter(token => token.type === 'code')
            .map(token => extractParamsFromText(token.text));
    } catch (error) {
        console.warn('Failed to extract code block parameters', error);
        return [];
    }
}

function enhanceCodeBlocks() {
    const contentArea = document.getElementById('contentArea');
    const codeBlocks = contentArea.querySelectorAll('pre > code');
    let blockIndex = 0;
    codeBlockWrappers = [];

    codeBlocks.forEach(codeBlock => {
        const pre = codeBlock.parentElement;

        if (!pre || (pre.parentElement && pre.parentElement.classList.contains('code-block'))) {
            return;
        }

        const wrapper = document.createElement('div');
        wrapper.className = 'code-block copyable-snippet';
        wrapper.setAttribute('data-copy-zone', 'true');
        wrapper.dataset.blockIndex = blockIndex;
        wrapper.dataset.params = JSON.stringify(codeBlockParamMap[blockIndex] || []);
        blockIndex++;

        pre.parentNode.insertBefore(wrapper, pre);
        wrapper.appendChild(pre);

        addCopyButton(wrapper, () => codeBlock.innerText || codeBlock.textContent || '');
        addSelectionCopyBehavior(wrapper);
    });

    attachSelectionCopyHandler();
}

function highlightHashComments() {
    const codeBlocks = document.querySelectorAll('#contentArea pre > code');

    codeBlocks.forEach(codeBlock => {
        const className = (codeBlock.className || '').toLowerCase();
        const langMatch = className.match(/language-([a-z0-9_+-]+)/);
        const language = langMatch ? langMatch[1] : '';

        const skipHashHighlight = ['markdown', 'python', 'c'];
        if (skipHashHighlight.includes(language)) {
            return;
        }

        const escapeHtml = (value) => value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        const lines = codeBlock.textContent.split('\n');
        let hasHashComments = false;

        const highlightedHtml = lines
            .map(line => {
                const match = line.match(/(^|\s)#/);

                if (!match) {
                    return escapeHtml(line);
                }

                const hashIndex = (match.index || 0) + match[1].length;
                hasHashComments = true;

                const codePart = line.slice(0, hashIndex);
                const commentPart = line.slice(hashIndex);

                return `${escapeHtml(codePart)}<span class="hash-comment">${escapeHtml(commentPart)}</span>`;
            })
            .join('\n');

        if (hasHashComments) {
            codeBlock.innerHTML = highlightedHtml;
        }
    });
}

function highlightParametersInCodeBlocks() {
    const wrappers = document.querySelectorAll('.code-block');

    wrappers.forEach(wrapper => {
        const codeBlock = wrapper.querySelector('code');
        if (!codeBlock) {
            return;
        }
        highlightMarkedParameters(codeBlock, false);
    });
}

function highlightParametersInText() {
    const contentArea = document.getElementById('contentArea');
    if (!contentArea) {
        return;
    }
    highlightMarkedParameters(contentArea, true, true);
}

function highlightMarkedParameters(element, skipCodeBlocks, preserveCodeBlockMarkers = false) {
    mergeAdjacentTextNodes(element);

    const walker = document.createTreeWalker(
        element,
        NodeFilter.SHOW_TEXT,
        {
            acceptNode(node) {
                if (!node.nodeValue || node.nodeValue.indexOf(PARAM_MARKER_START) === -1) {
                    return NodeFilter.FILTER_REJECT;
                }

                const parent = node.parentElement;
                if (!parent) return NodeFilter.FILTER_ACCEPT;

                if (parent.closest('.param-token')) return NodeFilter.FILTER_REJECT;
                if (parent.closest('input, textarea, button, .params-panel')) return NodeFilter.FILTER_REJECT;
                if (skipCodeBlocks && parent.closest('.code-block')) return NodeFilter.FILTER_REJECT;

                return NodeFilter.FILTER_ACCEPT;
            }
        }
    );

    const textNodes = [];
    let textNode;
    while ((textNode = walker.nextNode())) {
        textNodes.push(textNode);
    }

    textNodes.forEach(node => {
        wrapMarkersInTextNode(node);
    });

    cleanupResidualMarkers(element, preserveCodeBlockMarkers);
}

function mergeAdjacentTextNodes(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;

    while ((node = walker.nextNode())) {
        while (node.nextSibling && node.nextSibling.nodeType === Node.TEXT_NODE) {
            node.nodeValue += node.nextSibling.nodeValue;
            node.parentNode.removeChild(node.nextSibling);
        }
    }
}

function wrapMarkersInTextNode(node) {
    const text = node.nodeValue;
    const regex = new RegExp(`${PARAM_MARKER_START}([A-Z0-9_]+)${PARAM_SEPARATOR_REGEX}([\\s\\S]*?)${PARAM_MARKER_END}`, 'g');

    const matches = Array.from(text.matchAll(regex));
    if (!matches.length) {
        if (text.includes(PARAM_MARKER_START) || text.includes(PARAM_MARKER_END)) {
            const cleaned = text
                .replace(new RegExp(`${PARAM_MARKER_START}[A-Z0-9_]+${PARAM_SEPARATOR_REGEX}`, 'g'), '')
                .replace(new RegExp(PARAM_MARKER_END, 'g'), '');
            node.nodeValue = cleaned;
        }
        return;
    }

    const fragment = document.createDocumentFragment();
    let lastIndex = 0;

    matches.forEach(match => {
        const start = match.index || 0;
        const value = match[2];

        if (start > lastIndex) {
            fragment.appendChild(document.createTextNode(text.slice(lastIndex, start)));
        }

        const span = document.createElement('span');
        span.className = 'param-token';
        span.dataset.param = match[1];
        span.textContent = value;
        span.style.color = 'rgb(0, 255, 30)';
        span.style.fontWeight = 'bold';
        
        fragment.appendChild(span);

        lastIndex = (match.index || 0) + match[0].length;
    });

    if (lastIndex < text.length) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }

    node.parentNode.replaceChild(fragment, node);
}

function cleanupResidualMarkers(element, skipCodeBlocks = false) {
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    let node;

    while ((node = walker.nextNode())) {
        if (skipCodeBlocks && node.parentElement && node.parentElement.closest('.code-block')) {
            continue;
        }

        const value = node.nodeValue || '';
        if (!value.includes(PARAM_MARKER_START) && !value.includes(PARAM_MARKER_END)) {
            continue;
        }

        const cleaned = value
            .replace(new RegExp(`${PARAM_MARKER_START}[A-Z0-9_]+${PARAM_SEPARATOR_REGEX}`, 'g'), '')
            .replace(new RegExp(PARAM_MARKER_END, 'g'), '');

        if (cleaned !== value) {
            node.nodeValue = cleaned;
        }
    }
}

function getDisplayValueForParam(param) {
    const value = parameters[param];
    if (value === undefined || value === null || `${value}` === '') {
        return `<${param}>`;
    }
    return `${value}`;
}

function setupCodeBlockSelection() {
    const wrappers = document.querySelectorAll('.code-block');

    wrappers.forEach(wrapper => {
        wrapper.addEventListener('click', () => {
            selectCodeBlock(wrapper);
        });
    });

    if (!outsideClickListenerAttached) {
        document.addEventListener('click', (event) => {
            const clickedInsideCode = event.target.closest('.code-block');
            const clickedInsideParams = event.target.closest('#rightPanel');
            if (clickedInsideCode || clickedInsideParams) {
                return;
            }
            if (filteredParameters !== null || activeCodeBlock) {
                clearCodeBlockSelection();
            }
        });
        outsideClickListenerAttached = true;
    }

    if (activeCodeBlockIndex !== null) {
        const match = Array.from(wrappers).find(
            wrapper => Number(wrapper.dataset.blockIndex) === Number(activeCodeBlockIndex)
        );
        if (match) {
            if (suppressParamPanelRender) {
                activeCodeBlock = match;
                activeCodeBlock.classList.add('code-block-active');
                suppressParamPanelRender = false;
            } else {
                selectCodeBlock(match);
            }
        } else {
            suppressParamPanelRender = false;
        }
    }
}

function selectCodeBlock(wrapper) {
    if (!wrapper) {
        return;
    }

    if (activeCodeBlock && activeCodeBlock !== wrapper) {
        activeCodeBlock.classList.remove('code-block-active');
    }

    activeCodeBlock = wrapper;
    activeCodeBlockIndex = Number(wrapper.dataset.blockIndex);
    wrapper.classList.add('code-block-active');

    const params = parseParamsFromDataset(wrapper.dataset.params);
    filteredParameters = params;

    renderParametersPanel();
}

function parseParamsFromDataset(rawParams) {
    if (!rawParams) {
        return [];
    }
    try {
        const parsed = JSON.parse(rawParams);
        return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
        console.warn('Unable to parse code block parameters', error);
        return [];
    }
}

function clearCodeBlockSelection(skipRender = false) {
    if (activeCodeBlock) {
        activeCodeBlock.classList.remove('code-block-active');
    }
    activeCodeBlock = null;
    activeCodeBlockIndex = null;
    filteredParameters = null;

    if (!skipRender) {
        renderParametersPanel();
    }
}

function ensureParamSearchField() {
    const panel = document.querySelector('.params-panel');
    if (!panel) {
        return null;
    }

    let searchWrapper = panel.querySelector('.param-search');
    if (!searchWrapper) {
        searchWrapper = document.createElement('div');
        searchWrapper.className = 'param-search';

        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'param-search-input';
        input.placeholder = 'Search parameters';
        input.setAttribute('aria-label', 'Search parameters');

        searchWrapper.appendChild(input);

        const title = panel.querySelector('.panel-title');
        if (title) {
            title.insertAdjacentElement('afterend', searchWrapper);
        } else {
            panel.insertBefore(searchWrapper, panel.firstChild);
        }
    }

    if (filteredParameters !== null) {
        searchWrapper.classList.add('param-search-hidden');
    } else {
        searchWrapper.classList.remove('param-search-hidden');
    }

    const searchInput = searchWrapper.querySelector('.param-search-input');
    if (searchInput && !searchInput.dataset.bound) {
        searchInput.dataset.bound = 'true';
        searchInput.addEventListener('input', (e) => {
            paramSearchTerm = e.target.value;
            const caret = e.target.selectionStart || 0;
            renderParametersPanel();
            requestAnimationFrame(() => {
                const refreshedInput = document.querySelector('.param-search-input');
                if (refreshedInput) {
                    refreshedInput.focus();
                    refreshedInput.setSelectionRange(caret, caret);
                }
            });
        });
    }

    return searchInput || null;
}

function makeCheckboxesInteractive() {
    const contentArea = document.getElementById('contentArea');
    const listItems = contentArea.querySelectorAll('li');
    
    let checkboxIndex = 0;
    
    listItems.forEach(li => {
        const textContent = li.textContent || li.innerText;
        const existingCheckbox = li.querySelector('input[type="checkbox"]');
        const hasMarker = textContent.match(/^\s*\[([ xX])\]/) || Boolean(existingCheckbox);

        if (!hasMarker) {
            return;
        }

        if (existingCheckbox) {
            existingCheckbox.remove();
        }

        const isChecked = checkboxStates.get(checkboxIndex) || false;

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = isChecked;
        checkbox.dataset.index = checkboxIndex;
        checkbox.setAttribute('aria-label', `Task checkbox ${checkboxIndex + 1}`);
        
        checkbox.addEventListener('change', (e) => {
            const idx = parseInt(e.target.dataset.index);
            checkboxStates.set(idx, e.target.checked);
            persistCheckboxStates(currentPhase);
            
            e.target.style.transform = 'scale(1.2)';
            setTimeout(() => {
                e.target.style.transform = '';
            }, 200);
        });
        
        const originalHTML = li.innerHTML;
        const newHTML = originalHTML.replace(/^\s*\[([ xX])\]\s*/, '');
        li.innerHTML = newHTML;
        li.style.display = 'flex';
        li.style.alignItems = 'flex-start';
        li.insertBefore(checkbox, li.firstChild);
        
        checkboxIndex++;
    });
}

function extractParameters(content) {
    const accumulator = new Set(getAllParameterNames());
    collectParametersFromContent(content, accumulator);
    allDiscoveredParameters = Array.from(accumulator).sort();
    hydrateParametersFromStorage();
    renderParametersPanel();
}

function extractParamsFromText(text) {
    const matches = text.match(PARAM_TOKEN_REGEX);
    return matches ? [...new Set(matches.map(token => token.replace(/[<>{}]/g, '')))] : [];
}

function collectParametersFromContent(content, accumulator) {
    if (!accumulator) {
        return;
    }
    extractParamsFromText(content).forEach(param => accumulator.add(param));
}

function getAllParameterNames() {
    const baseNames = Array.isArray(CORE_PARAMETER_NAMES) ? CORE_PARAMETER_NAMES : [];
    const combined = new Set(baseNames);

    if (Array.isArray(allDiscoveredParameters) && allDiscoveredParameters.length) {
        allDiscoveredParameters.forEach(param => combined.add(param));
    }

    if (parameters && typeof parameters === 'object') {
        Object.keys(parameters).forEach(param => combined.add(param));
    }

    return Array.from(combined);
}

function renderParametersPanel() {
    const container = document.getElementById('paramsContainer');
    const allParams = getAllParameterNames();
    const hasAnyParameters = allParams.length > 0;
    const baseParams = filteredParameters !== null ? filteredParameters : allParams;
    const searchTerm = paramSearchTerm.trim().toLowerCase();
    let displayParams = baseParams.slice().sort();

    if (searchTerm) {
        displayParams = displayParams.filter(param => param.toLowerCase().includes(searchTerm));
    }

    const hasDisplayParams = displayParams.length > 0;

    toggleLayoutForParameters(hasAnyParameters);

    const searchInput = ensureParamSearchField();
    if (searchInput) {
        searchInput.value = paramSearchTerm;
    }
    
    if (!hasDisplayParams) {
        const message = !hasAnyParameters
            ? 'No parameters found in this phase'
            : (searchTerm
                ? 'No parameters match your search'
                : (filteredParameters !== null
                    ? 'No parameters found for this code block'
                    : 'No parameters found in this phase'));
        container.innerHTML = `<p class="text-secondary" style="color: var(--text-secondary); font-size: 0.875rem; text-align: center; padding: 1rem;">${message}</p>`;
        return;
    }
    
    let html = '';
    displayParams.forEach(param => {
        html += `
            <div class="param-group">
                <label class="param-label">${param}</label>
                <input type="text" 
                       class="param-input" 
                       data-param="${param}" 
                       value="${parameters[param] || ''}" 
                       placeholder="Enter ${param.toLowerCase().replace(/_/g, ' ')}"
                       aria-label="Parameter input for ${param}">
            </div>
        `;
    });
    
    container.innerHTML = html;
    
    container.querySelectorAll('.param-input').forEach(input => {
        input.addEventListener('input', (e) => {
            const scrollPos = document.getElementById('contentArea').scrollTop;
            parameters[e.target.dataset.param] = e.target.value;
            persistParameters();
            suppressParamPanelRender = filteredParameters !== null;
            updateContent(scrollPos);
        });

        input.addEventListener('focus', (e) => {
            e.target.parentElement.style.transform = 'translateX(4px)';
        });

        input.addEventListener('blur', (e) => {
            e.target.parentElement.style.transform = '';
        });
    });
}

function updateContent(scrollPos = null) {
    renderContent();
    
    if (scrollPos !== null) {
        document.getElementById('contentArea').scrollTop = scrollPos;
    }
}

function toggleRightPanel() {
    const rightPanel = document.getElementById('rightPanel');
    rightPanel.classList.toggle('collapsed');
    localStorage.setItem('rightPanelCollapsed', rightPanel.classList.contains('collapsed'));
}

function toggleLayoutForParameters(hasParameters) {
    const centerPanel = document.getElementById('centerPanel');
    const rightPanel = document.getElementById('rightPanel');

    if (!centerPanel || !rightPanel) {
        return;
    }

    if (hasParameters) {
        centerPanel.classList.remove('col-lg-10', 'col-md-9');
        centerPanel.classList.add('col-lg-7', 'col-md-6');
        rightPanel.classList.remove('d-none');
        
        const wasCollapsed = localStorage.getItem('rightPanelCollapsed') === 'true';
        if (wasCollapsed) {
            rightPanel.classList.add('collapsed');
        }
    } else {
        centerPanel.classList.remove('col-lg-7', 'col-md-6');
        centerPanel.classList.add('col-lg-10', 'col-md-9');
        rightPanel.classList.add('d-none');
    }
}

function loadCheckboxStatesFromStorage(phase) {
    const stored = getStoredCheckboxState()[phase];
    return Array.isArray(stored) ? stored.map(value => Boolean(value)) : null;
}

function persistCheckboxStates(phase) {
    const allCheckboxStates = getStoredCheckboxState();
    const stateArray = [];

    checkboxStates.forEach((value, key) => {
        stateArray[key] = value;
    });

    allCheckboxStates[phase] = stateArray;
    localStorage.setItem(CHECKBOX_STORAGE_KEY, JSON.stringify(allCheckboxStates));
    updateResetButtonVisibility();
}

function getStoredCheckboxState() {
    try {
        const raw = localStorage.getItem(CHECKBOX_STORAGE_KEY);
        return raw ? JSON.parse(raw) : {};
    } catch (error) {
        console.warn('Could not read checkbox state from localStorage', error);
        return {};
    }
}

function getStoredParameters() {
    try {
        const raw = localStorage.getItem(PARAMS_STORAGE_KEY);
        return raw ? JSON.parse(raw) : {};
    } catch (error) {
        console.warn('Could not read parameters from localStorage', error);
        return {};
    }
}

function hydrateParametersFromStorage() {
    const stored = getStoredParameters();
    const hydrated = {};
    const paramNames = new Set([...getAllParameterNames(), ...Object.keys(stored || {})]);

    paramNames.forEach(param => {
        const storedValue = stored[param];
        hydrated[param] = storedValue === undefined || storedValue === null ? '' : `${storedValue}`;
    });

    parameters = hydrated;
    persistParameters();
}

function persistParameters() {
    localStorage.setItem(PARAMS_STORAGE_KEY, JSON.stringify(parameters));
    updateResetButtonVisibility();
}

function refreshContentFromParameters() {
    const contentArea = document.getElementById('contentArea');
    const scrollPos = contentArea ? contentArea.scrollTop : null;
    renderContent();
    if (scrollPos !== null) {
        contentArea.scrollTop = scrollPos;
    }
}

function syncParameterValue(paramName, value, options = {}) {
    if (!paramName) {
        return false;
    }

    const normalized = value === undefined || value === null ? '' : `${value}`.trim();
    const existing = parameters[paramName] === undefined ? '' : `${parameters[paramName]}`;
    const changed = existing !== normalized;

    if (changed) {
        parameters[paramName] = normalized;
        persistParameters();
    }

    if (options.updatePanel !== false) {
        const panelInput = document.querySelector(`.param-input[data-param="${paramName}"]`);
        if (panelInput && panelInput.value !== normalized) {
            panelInput.value = normalized;
        } else if (!panelInput) {
            renderParametersPanel();
        }
    }

    if (options.refreshPanel) {
        renderParametersPanel();
    }

    if (options.refreshContent) {
        refreshContentFromParameters();
    }

    return changed;
}

function hasStoredCheckboxData() {
    const stored = getStoredCheckboxState();
    return Object.values(stored).some(value => Array.isArray(value) && value.length > 0);
}

function hasStoredParameterData() {
    return hasAnyParameterValue(parameters) || hasAnyParameterValue(getStoredParameters());
}

function hasAnyParameterValue(paramMap = parameters) {
    if (!paramMap || typeof paramMap !== 'object') {
        return false;
    }

    return Object.values(paramMap).some(value => {
        if (value === undefined || value === null) {
            return false;
        }
        return `${value}`.trim() !== '';
    });
}

function updateResetButtonVisibility() {
    const resetBtn = document.getElementById('newAssessmentBtn');
    if (!resetBtn) {
        return;
    }

    const shouldShow = hasStoredParameterData() || hasStoredCheckboxData();
    resetBtn.hidden = !shouldShow;
}

function resetAssessment() {
    localStorage.removeItem(CHECKBOX_STORAGE_KEY);
    localStorage.removeItem(PARAMS_STORAGE_KEY);
    localStorage.removeItem(INITIAL_PARAMS_SKIPPED_KEY);
    checkboxStates.clear();
    parameters = {};
    initialParamsPromptShown = false;
    hydrateParametersFromStorage();
    
    if (currentPhase) {
        loadPhase(currentPhase);
    } else {
        renderParametersPanel();
    }

    updateResetButtonVisibility();
    showResetToast();
}

function showResetToast() {
    const toast = document.getElementById('resetToast');
    if (!toast) return;

    toast.classList.add('show');

    if (resetToastTimeout) {
        clearTimeout(resetToastTimeout);
    }

    resetToastTimeout = setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function resetContentScroll() {
    const contentArea = document.getElementById('contentArea');
    if (contentArea) {
        contentArea.scrollTop = 0;
    }
}

function maybeShowInitialParamsModal() {
    if (initialParamsPromptShown) {
        return;
    }

    if (isInitialParamsSkipped()) {
        return;
    }

    if (!getAllParameterNames().length) {
        return;
    }

    if (hasAnyParameterValue(parameters)) {
        return;
    }

    if (typeof openInitialParamsModal === 'function') {
        openInitialParamsModal();
    }
}

function isInitialParamsSkipped() {
    try {
        return localStorage.getItem(INITIAL_PARAMS_SKIPPED_KEY) === 'true';
    } catch (error) {
        console.warn('Could not read initial modal skip state', error);
        return false;
    }
}

function extractPlainTextFromMarkdown(content) {
    if (!content) {
        return '';
    }

    const wrapper = document.createElement('div');
    wrapper.innerHTML = marked.parse(content);
    return wrapper.textContent || '';
}

function setupGlobalSearchModal() {
    const modal = document.getElementById('globalSearchModal');
    const button = document.getElementById('globalSearchBtn');
    const input = document.getElementById('globalSearchInput');
    const resultsContainer = document.getElementById('globalSearchResults');

    if (!modal || !button || !input || !resultsContainer || modal.dataset.initialized === 'true') {
        return;
    }

    const render = () => {
        renderGlobalSearchResults(input.value.trim(), resultsContainer, modal);
    };

    button.addEventListener('click', () => {
        if (typeof openModal === 'function') {
            openModal(modal);
        } else {
            modal.classList.add('show');
            modal.setAttribute('aria-hidden', 'false');
        }
        input.focus();
        input.select();
    });

    input.addEventListener('input', render);
    input.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            const firstResult = resultsContainer.querySelector('.global-search-result');
            if (firstResult) {
                firstResult.click();
            }
        }
    });

    document.addEventListener('keydown', (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'f') {
            event.preventDefault();
            if (typeof openModal === 'function') {
                openModal(modal);
            } else {
                modal.classList.add('show');
                modal.setAttribute('aria-hidden', 'false');
            }
            input.focus();
            input.select();
        }
    });

    renderGlobalSearchResults('', resultsContainer, modal);
    modal.dataset.initialized = 'true';
}

function renderGlobalSearchResults(term, resultsContainer, modal) {
    resultsContainer.innerHTML = '';

    if (!term) {
        const placeholder = document.createElement('div');
        placeholder.className = 'global-search-placeholder';
        placeholder.textContent = 'Start typing to search across every note.';
        resultsContainer.appendChild(placeholder);
        return;
    }

    const results = buildGlobalSearchMatches(term);
    if (!results.length) {
        const empty = document.createElement('div');
        empty.className = 'global-search-empty';
        empty.textContent = 'No matches found in your notes.';
        resultsContainer.appendChild(empty);
        return;
    }

    const count = document.createElement('p');
    count.className = 'global-search-count';
    count.textContent = `${results.length} match${results.length === 1 ? '' : 'es'} found`;
    resultsContainer.appendChild(count);

    results.forEach(result => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'global-search-result';
        item.dataset.phase = result.phase;
        item.dataset.matchIndex = `${result.matchIndex}`;

        const title = document.createElement('div');
        title.className = 'global-search-result-title';
        title.textContent = formatPhaseLabel(result.phase);

        const meta = document.createElement('div');
        meta.className = 'global-search-result-meta';
        meta.textContent = `Match ${result.matchIndex + 1}`;

        const snippet = document.createElement('div');
        snippet.className = 'global-search-result-snippet';
        appendHighlightedSnippetLines(snippet, result.lines, term, result.matchLineIndex, result.prefix, result.suffix);

        item.append(title, meta, snippet);
        item.addEventListener('click', () => {
            jumpToGlobalSearchMatch(result.phase, term, result.matchIndex);
        });

        resultsContainer.appendChild(item);
    });
}

function buildGlobalSearchMatches(term) {
    const results = [];
    const needle = term.toLowerCase();

    Object.entries(phases).forEach(([phase, content]) => {
        const text = phaseTextIndex[phase] || extractPlainTextFromMarkdown(content);
        phaseTextIndex[phase] = text;
        const lines = text.split('\n');
        let matchIndex = 0;

        lines.forEach((line, lineIndex) => {
            if (!needle) {
                return;
            }
            if (!line.toLowerCase().includes(needle)) {
                return;
            }
            const snippet = buildSearchSnippetLines(lines, lineIndex);
            results.push({
                phase,
                matchIndex,
                lines: snippet.lines,
                matchLineIndex: snippet.matchLineIndex,
                prefix: snippet.prefix,
                suffix: snippet.suffix
            });
            matchIndex += 1;
        });
    });

    return results;
}

function buildSearchSnippetLines(lines, matchLineIndex) {
    const start = Math.max(0, matchLineIndex - 2);
    const end = Math.min(lines.length - 1, matchLineIndex + 2);
    const snippetLines = lines.slice(start, end + 1);

    return {
        lines: snippetLines.map(line => line.replace(/\s+$/g, '')),
        matchLineIndex: matchLineIndex - start,
        prefix: start > 0,
        suffix: end < lines.length - 1
    };
}

function appendHighlightedSnippetLines(container, lines, term, matchLineIndex, prefix, suffix) {
    const lowerTerm = term.toLowerCase();

    if (prefix) {
        const ellipsis = document.createElement('div');
        ellipsis.className = 'global-search-snippet-ellipsis';
        ellipsis.textContent = '...';
        container.appendChild(ellipsis);
    }

    lines.forEach((line, index) => {
        const lineEl = document.createElement('div');
        lineEl.className = 'global-search-snippet-line';
        const lowerLine = line.toLowerCase();
        const matchIndex = lowerLine.indexOf(lowerTerm);
        if (matchIndex === -1) {
            lineEl.textContent = line;
        } else {
            const before = line.slice(0, matchIndex);
            const matchText = line.slice(matchIndex, matchIndex + term.length);
            const after = line.slice(matchIndex + term.length);
            lineEl.appendChild(document.createTextNode(before));
            const highlight = document.createElement('span');
            highlight.className = 'global-search-match';
            highlight.textContent = matchText;
            lineEl.appendChild(highlight);
            lineEl.appendChild(document.createTextNode(after));
        }
        container.appendChild(lineEl);
    });

    if (suffix) {
        const ellipsis = document.createElement('div');
        ellipsis.className = 'global-search-snippet-ellipsis';
        ellipsis.textContent = '...';
        container.appendChild(ellipsis);
    }
}

function formatPhaseLabel(phase) {
    return phase.replace('notes/', '').replace('.md', '');
}

function jumpToGlobalSearchMatch(phase, term, matchIndex) {
    if (!phase || !phases[phase]) {
        return;
    }

    document.querySelectorAll('.phase-btn').forEach(button => {
        button.classList.toggle('active', button.dataset.phase === phase);
    });

    currentPhase = phase;
    checkboxStates.clear();
    loadPhase(phase);

    requestAnimationFrame(() => {
        const found = highlightGlobalSearchMatch(term, matchIndex);
        if (!found) {
            resetContentScroll();
        }
    });
}

function highlightGlobalSearchMatch(term, matchIndex) {
    if (!term) {
        return false;
    }

    const contentArea = document.getElementById('contentArea');
    if (!contentArea) {
        return false;
    }

    clearGlobalSearchHighlights();

    const lowerTerm = term.toLowerCase();
    const walker = document.createTreeWalker(contentArea, NodeFilter.SHOW_TEXT, {
        acceptNode(node) {
            if (!node.nodeValue) {
                return NodeFilter.FILTER_REJECT;
            }
            if (node.parentElement && node.parentElement.closest('script, style')) {
                return NodeFilter.FILTER_REJECT;
            }
            return NodeFilter.FILTER_ACCEPT;
        }
    });

    let node = walker.nextNode();
    let count = 0;

    while (node) {
        const text = node.nodeValue;
        const lowerText = text.toLowerCase();
        let index = 0;

        while ((index = lowerText.indexOf(lowerTerm, index)) !== -1) {
            if (count === matchIndex) {
                const matchNode = wrapTextMatch(node, index, index + term.length);
                if (matchNode) {
                    matchNode.classList.add('global-search-hit-active');
                    matchNode.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    return true;
                }
            }
            count += 1;
            index += lowerTerm.length;
        }

        node = walker.nextNode();
    }

    return false;
}

function wrapTextMatch(node, start, end) {
    const text = node.nodeValue || '';
    const parent = node.parentNode;
    if (!parent) {
        return null;
    }

    const beforeText = text.slice(0, start);
    const matchText = text.slice(start, end);
    const afterText = text.slice(end);

    const beforeNode = document.createTextNode(beforeText);
    const matchNode = document.createElement('span');
    matchNode.className = 'global-search-hit';
    matchNode.textContent = matchText;
    const afterNode = document.createTextNode(afterText);

    parent.insertBefore(beforeNode, node);
    parent.insertBefore(matchNode, node);
    parent.insertBefore(afterNode, node);
    parent.removeChild(node);

    return matchNode;
}

function clearGlobalSearchHighlights() {
    document.querySelectorAll('.global-search-hit').forEach(hit => {
        const parent = hit.parentNode;
        if (!parent) {
            return;
        }
        parent.replaceChild(document.createTextNode(hit.textContent || ''), hit);
        parent.normalize();
    });
}
