let globalSearchIndex = {};
let globalSearchUi = null;
let globalSearchRenderTimeout = null;
let globalSearchLastTerm = '';
let globalSearchLastFilterKey = '';
let globalSearchActiveMatch = null;
let globalSearchHighlightTimeout = null;
let globalSearchFilters = {
    phases: new Set(),
    types: new Set()
};

const GLOBAL_SEARCH_TYPES = [
    { key: 'text', label: 'Text' },
    { key: 'snippet', label: 'Snippets' },
    { key: 'table', label: 'Tables' }
];

const GLOBAL_SEARCH_TYPE_LABELS = {
    text: 'Text',
    snippet: 'Snippet',
    table: 'Table'
};

const GLOBAL_SEARCH_MIN_TERM_LENGTH = 2;
const GLOBAL_SEARCH_RESULT_LIMIT = 200;

async function loadMarkdownFiles() {
    const mdFiles = [
        '01 - Reconnaissance & Enumeration.md',
        '02 - Vulnerability Research & Exploitation.md',
        '03 - Active Directory Exploitation.md',
        '04 - Post Exploitation & Privilege Escalation.md',
        '05 - Lateral Movement.md',
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

    buildGlobalSearchIndex();
    refreshGlobalSearchPhaseFilters();
    refreshGlobalSearchResults(true);

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
    restoreGlobalSearchHighlight();
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
    const phaseFiltersContainer = document.getElementById('globalSearchPhaseFilters');
    const typeFiltersContainer = document.getElementById('globalSearchTypeFilters');

    if (!modal || !button || !input || !resultsContainer || !phaseFiltersContainer || !typeFiltersContainer || modal.dataset.initialized === 'true') {
        return;
    }

    globalSearchUi = {
        modal,
        input,
        resultsContainer,
        phaseFiltersContainer,
        typeFiltersContainer
    };

    renderGlobalSearchTypeFilters();
    refreshGlobalSearchPhaseFilters();

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

    input.addEventListener('input', () => scheduleGlobalSearchRender());
    input.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            const firstResult = resultsContainer.querySelector('.global-search-result');
            if (firstResult) {
                firstResult.click();
            }
        }
    });

    renderGlobalSearchResults('', resultsContainer, modal, { force: true });
    modal.dataset.initialized = 'true';
}

function refreshGlobalSearchResults(force = false) {
    if (!globalSearchUi) {
        return;
    }
    renderGlobalSearchResults(
        globalSearchUi.input.value.trim(),
        globalSearchUi.resultsContainer,
        globalSearchUi.modal,
        { force }
    );
}

function scheduleGlobalSearchRender(delay = 160) {
    if (!globalSearchUi) {
        return;
    }
    if (globalSearchRenderTimeout) {
        clearTimeout(globalSearchRenderTimeout);
    }
    globalSearchRenderTimeout = setTimeout(() => {
        refreshGlobalSearchResults();
    }, delay);
}

function renderGlobalSearchTypeFilters() {
    const container = globalSearchUi?.typeFiltersContainer || document.getElementById('globalSearchTypeFilters');
    if (!container) {
        return;
    }

    if (!globalSearchFilters.types.size) {
        GLOBAL_SEARCH_TYPES.forEach(type => globalSearchFilters.types.add(type.key));
    }

    container.innerHTML = '';

    GLOBAL_SEARCH_TYPES.forEach(type => {
        const chip = createGlobalSearchChip(type.label, globalSearchFilters.types.has(type.key));
        chip.dataset.type = type.key;
        chip.addEventListener('click', () => {
            toggleGlobalSearchFilter(globalSearchFilters.types, type.key, GLOBAL_SEARCH_TYPES.map(item => item.key));
            renderGlobalSearchTypeFilters();
            refreshGlobalSearchResults(true);
        });
        container.appendChild(chip);
    });
}

function refreshGlobalSearchPhaseFilters() {
    const container = globalSearchUi?.phaseFiltersContainer || document.getElementById('globalSearchPhaseFilters');
    if (!container) {
        return;
    }

    const phaseKeys = Object.keys(phases);
    container.innerHTML = '';

    if (!phaseKeys.length) {
        return;
    }

    if (!globalSearchFilters.phases.size) {
        phaseKeys.forEach(phase => globalSearchFilters.phases.add(phase));
    } else {
        const activePhases = new Set(globalSearchFilters.phases);
        globalSearchFilters.phases.clear();
        phaseKeys.forEach(phase => {
            if (activePhases.has(phase)) {
                globalSearchFilters.phases.add(phase);
            }
        });
        if (!globalSearchFilters.phases.size) {
            phaseKeys.forEach(phase => globalSearchFilters.phases.add(phase));
        }
    }

    phaseKeys.forEach(phase => {
        const chip = createGlobalSearchChip(formatPhaseLabel(phase), globalSearchFilters.phases.has(phase));
        chip.dataset.phase = phase;
        chip.addEventListener('click', () => {
            toggleGlobalSearchFilter(globalSearchFilters.phases, phase, phaseKeys);
            refreshGlobalSearchPhaseFilters();
            refreshGlobalSearchResults(true);
        });
        container.appendChild(chip);
    });
}

function toggleGlobalSearchFilter(filterSet, value, allValues) {
    if (filterSet.has(value)) {
        if (filterSet.size === 1) {
            return;
        }
        filterSet.delete(value);
        return;
    }

    filterSet.add(value);

    if (!filterSet.size) {
        allValues.forEach(item => filterSet.add(item));
    }
}

function createGlobalSearchChip(label, isActive) {
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = `global-search-chip${isActive ? ' active' : ''}`;
    chip.textContent = label;
    return chip;
}

function buildGlobalSearchIndex() {
    const index = {};

    Object.entries(phases).forEach(([phase, content]) => {
        let tokens = [];
        try {
            tokens = marked.lexer(content || '');
        } catch (error) {
            console.warn('Failed to parse markdown for search index', error);
        }

        const segments = [];
        tokens.forEach(token => collectSearchSegmentsFromToken(token, segments));
        index[phase] = segments;
    });

    globalSearchIndex = index;
}

function collectSearchSegmentsFromToken(token, segments) {
    if (!token) {
        return;
    }

    switch (token.type) {
        case 'heading':
        case 'paragraph':
        case 'list':
        case 'blockquote':
        case 'html':
        case 'text':
            addSearchSegment('text', getTokenMarkdown(token), segments);
            break;
        case 'code':
            addSearchSegment('snippet', getTokenMarkdown(token), segments);
            break;
        case 'table':
            addSearchSegment('table', getTokenMarkdown(token), segments);
            break;
        default:
            if (Array.isArray(token.tokens)) {
                token.tokens.forEach(innerToken => collectSearchSegmentsFromToken(innerToken, segments));
            }
            break;
    }
}

function getTokenMarkdown(token) {
    if (token?.raw) {
        return token.raw.trim();
    }

    switch (token?.type) {
        case 'code': {
            const lang = token.lang ? token.lang.trim() : '';
            return `\`\`\`${lang}\n${token.text || ''}\n\`\`\``;
        }
        case 'table':
            return buildMarkdownTable(token);
        case 'list':
            return buildMarkdownList(token);
        case 'blockquote':
            return token.text
                ? token.text.split('\n').map(line => `> ${line}`).join('\n')
                : '';
        default:
            return token?.text || '';
    }
}

function buildMarkdownTable(token) {
    const header = Array.isArray(token?.header) ? token.header : [];
    const rows = Array.isArray(token?.rows) ? token.rows : [];

    if (!header.length && !rows.length) {
        return '';
    }

    const separator = header.map(() => '---');
    const lines = [
        `| ${header.join(' | ')} |`,
        `| ${separator.join(' | ')} |`
    ];

    rows.forEach(row => {
        lines.push(`| ${row.join(' | ')} |`);
    });

    return lines.join('\n');
}

function buildMarkdownList(token) {
    const items = Array.isArray(token?.items) ? token.items : [];
    if (!items.length) {
        return '';
    }

    const start = Number.isFinite(token.start) ? token.start : 1;
    const ordered = Boolean(token.ordered);

    return items.map((item, index) => {
        const prefix = ordered ? `${start + index}. ` : '- ';
        let text = item?.text || '';
        if (item?.task) {
            const check = item.checked ? 'x' : ' ';
            text = `[${check}] ${text}`;
        }
        return `${prefix}${text}`;
    }).join('\n');
}

function addSearchSegment(type, markdown, segments) {
    const trimmed = (markdown || '').trim();
    if (!trimmed) {
        return;
    }

    const plainText = extractPlainTextFromMarkdown(trimmed);
    segments.push({
        type,
        markdown: trimmed,
        html: marked.parse(trimmed),
        plainText,
        lowerText: plainText.toLowerCase(),
        highlightCache: {
            term: '',
            template: null
        }
    });
}

function renderGlobalSearchResults(term, resultsContainer, modal, options = {}) {
    const filterKey = getGlobalSearchFilterKey();
    if (!options.force && term === globalSearchLastTerm && filterKey === globalSearchLastFilterKey) {
        return;
    }
    globalSearchLastTerm = term;
    globalSearchLastFilterKey = filterKey;

    resultsContainer.innerHTML = '';

    if (!term) {
        const placeholder = document.createElement('div');
        placeholder.className = 'global-search-placeholder';
        placeholder.textContent = 'Start typing to search across every note.';
        resultsContainer.appendChild(placeholder);
        return;
    }

    if (term.length < GLOBAL_SEARCH_MIN_TERM_LENGTH) {
        const empty = document.createElement('div');
        empty.className = 'global-search-empty';
        empty.textContent = `Type at least ${GLOBAL_SEARCH_MIN_TERM_LENGTH} characters to search.`;
        resultsContainer.appendChild(empty);
        return;
    }

    if (!Object.keys(globalSearchIndex).length) {
        const empty = document.createElement('div');
        empty.className = 'global-search-empty';
        empty.textContent = 'No notes loaded yet.';
        resultsContainer.appendChild(empty);
        return;
    }

    const { results, limited } = buildGlobalSearchMatches(term);
    if (!results.length) {
        const empty = document.createElement('div');
        empty.className = 'global-search-empty';
        empty.textContent = 'No matches found in your notes.';
        resultsContainer.appendChild(empty);
        return;
    }

    const count = document.createElement('p');
    count.className = 'global-search-count';
    count.textContent = limited
        ? `Showing first ${results.length} matches. Refine to see more.`
        : `${results.length} match${results.length === 1 ? '' : 'es'} found`;
    resultsContainer.appendChild(count);

    const fragment = document.createDocumentFragment();

    results.forEach(result => {
        const item = document.createElement('div');
        item.className = 'global-search-result';
        item.dataset.phase = result.phase;
        item.dataset.matchIndex = `${result.matchIndex}`;
        item.setAttribute('role', 'button');
        item.setAttribute('tabindex', '0');

        const title = document.createElement('div');
        title.className = 'global-search-result-title';
        title.textContent = formatPhaseLabel(result.phase);

        const meta = document.createElement('div');
        meta.className = 'global-search-result-meta';
        meta.textContent = `Match ${result.matchIndex + 1} • ${result.typeLabel}`;

        const content = document.createElement('div');
        content.className = 'global-search-result-content';

        const template = getSegmentHighlightTemplate(result.segment, term);
        if (template) {
            content.appendChild(template.cloneNode(true));
        }

        item.append(title, meta, content);

        const handleSelect = () => {
            jumpToGlobalSearchMatch(result.phase, term, result.matchIndex);
            if (typeof closeModal === 'function') {
                closeModal(modal);
            } else if (modal) {
                modal.classList.remove('show');
                modal.setAttribute('aria-hidden', 'true');
                if (!document.querySelector('.pwn-modal.show')) {
                    document.body.classList.remove('modal-open');
                }
            }
        };

        item.addEventListener('click', handleSelect);
        item.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                handleSelect();
            }
        });

        fragment.appendChild(item);
    });

    resultsContainer.appendChild(fragment);
}

function buildGlobalSearchMatches(term) {
    const results = [];
    const needle = term.toLowerCase();
    let limited = false;

    for (const [phase, segments] of Object.entries(globalSearchIndex)) {
        if (globalSearchFilters.phases.size && !globalSearchFilters.phases.has(phase)) {
            continue;
        }

        let matchIndex = 0;

        for (const segment of segments) {
            if (!globalSearchFilters.types.has(segment.type)) {
                continue;
            }

            const remaining = GLOBAL_SEARCH_RESULT_LIMIT - results.length;
            if (remaining <= 0) {
                limited = true;
                break;
            }

            const positions = findTermPositionsInLowerText(segment.lowerText, needle, remaining);
            if (!positions.length) {
                continue;
            }

            for (let i = 0; i < positions.length; i += 1) {
                results.push({
                    phase,
                    matchIndex,
                    type: segment.type,
                    typeLabel: GLOBAL_SEARCH_TYPE_LABELS[segment.type] || segment.type,
                    segment
                });
                matchIndex += 1;

                if (results.length >= GLOBAL_SEARCH_RESULT_LIMIT) {
                    limited = true;
                    break;
                }
            }

            if (limited) {
                break;
            }
        }

        if (limited) {
            break;
        }
    }

    return { results, limited };
}

function findTermPositionsInLowerText(text, needle, maxCount = Infinity) {
    const positions = [];
    if (!text || !needle) {
        return positions;
    }

    let index = 0;

    while ((index = text.indexOf(needle, index)) !== -1) {
        positions.push(index);
        index += needle.length;
        if (positions.length >= maxCount) {
            break;
        }
    }

    return positions;
}

function formatPhaseLabel(phase) {
    return phase.replace('notes/', '').replace('.md', '');
}

function getGlobalSearchFilterKey() {
    const phasesKey = Array.from(globalSearchFilters.phases).sort().join('|');
    const typesKey = Array.from(globalSearchFilters.types).sort().join('|');
    return `${phasesKey}::${typesKey}`;
}

function getSegmentHighlightTemplate(segment, term) {
    if (!segment || !term) {
        return null;
    }

    if (segment.highlightCache.term === term && segment.highlightCache.template) {
        return segment.highlightCache.template;
    }

    const wrapper = document.createElement('div');
    wrapper.innerHTML = segment.html || '';
    highlightAllOccurrencesInElement(wrapper, term, 'global-search-match');

    segment.highlightCache.term = term;
    segment.highlightCache.template = wrapper;

    return wrapper;
}

function highlightAllOccurrencesInElement(element, term, className) {
    if (!element || !term) {
        return 0;
    }

    const lowerTerm = term.toLowerCase();
    const nodes = [];
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, {
        acceptNode(node) {
            if (!node.nodeValue) {
                return NodeFilter.FILTER_REJECT;
            }
            return NodeFilter.FILTER_ACCEPT;
        }
    });

    let node = walker.nextNode();
    while (node) {
        nodes.push(node);
        node = walker.nextNode();
    }

    let totalMatches = 0;
    nodes.forEach(textNode => {
        const text = textNode.nodeValue;
        const lowerText = text.toLowerCase();
        if (!lowerText.includes(lowerTerm)) {
            return;
        }

        const fragment = document.createDocumentFragment();
        let cursor = 0;
        let index = 0;

        while ((index = lowerText.indexOf(lowerTerm, cursor)) !== -1) {
            if (index > cursor) {
                fragment.appendChild(document.createTextNode(text.slice(cursor, index)));
            }
            const matchNode = document.createElement('span');
            matchNode.className = className;
            matchNode.textContent = text.slice(index, index + term.length);
            fragment.appendChild(matchNode);
            cursor = index + term.length;
            totalMatches += 1;
        }

        if (cursor < text.length) {
            fragment.appendChild(document.createTextNode(text.slice(cursor)));
        }

        const parent = textNode.parentNode;
        if (parent) {
            parent.replaceChild(fragment, textNode);
        }
    });

    return totalMatches;
}

function jumpToGlobalSearchMatch(phase, term, matchIndex) {
    if (!phase || !phases[phase]) {
        return;
    }

    globalSearchActiveMatch = { phase, term, matchIndex };
    document.querySelectorAll('.phase-btn').forEach(button => {
        button.classList.toggle('active', button.dataset.phase === phase);
    });

    currentPhase = phase;
    checkboxStates.clear();
    loadPhase(phase);

    requestAnimationFrame(() => {
        restoreGlobalSearchHighlight({ ensureVisible: true });
        scheduleGlobalSearchHighlightClear();
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
                const matchNode = wrapTextMatch(node, index, index + term.length, 'global-search-hit');
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

function restoreGlobalSearchHighlight(options = {}) {
    if (!globalSearchActiveMatch || globalSearchActiveMatch.phase !== currentPhase) {
        return false;
    }

    const contentArea = document.getElementById('contentArea');
    if (!contentArea) {
        return false;
    }

    const existingHit = contentArea.querySelector('.global-search-hit-active');
    if (existingHit) {
        if (options.ensureVisible) {
            existingHit.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
        return true;
    }

    const found = highlightGlobalSearchMatch(globalSearchActiveMatch.term, globalSearchActiveMatch.matchIndex);
    if (options.ensureVisible && !found) {
        resetContentScroll();
    }
    return found;
}

function scheduleGlobalSearchHighlightClear(delay = 5000) {
    if (globalSearchHighlightTimeout) {
        clearTimeout(globalSearchHighlightTimeout);
    }

    globalSearchHighlightTimeout = setTimeout(() => {
        clearGlobalSearchHighlights();
        globalSearchActiveMatch = null;
        globalSearchHighlightTimeout = null;
    }, delay);
}

function wrapTextMatch(node, start, end, className = 'global-search-hit') {
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
    matchNode.className = className;
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
