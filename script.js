let currentPhase = null;
let parameters = {};
let phases = {};
let currentContent = '';
let checkboxStates = new Map();
let filteredParameters = null;
let activeCodeBlock = null;
let activeCodeBlockIndex = null;
let codeBlockParamMap = [];
let outsideClickListenerAttached = false;
let suppressParamPanelRender = false;
let paramSearchTerm = '';
let resetToastTimeout = null;
let codeBlockWrappers = [];
let selectionCopyHandlerAttached = false;
let lastCopiedSelection = '';
let lastCopiedWrapper = null;
let lastCopiedAt = 0;
const CHECKBOX_STORAGE_KEY = 'checkboxStates';
const PARAMS_STORAGE_KEY = 'parameters';
const PARAM_TOKEN_REGEX = /(<[A-Z_0-9]+>|{{[A-Z_0-9]+}})/g;

document.addEventListener('DOMContentLoaded', () => {
    loadMarkdownFiles();
    setupEventListeners();
    setupMarkedOptions();
    updateResetButtonVisibility();
});

function setupMarkedOptions() {
    // Configure marked to open external links in new tabs
    const renderer = new marked.Renderer();
    const originalLinkRenderer = renderer.link;
    
    renderer.link = function(href, title, text) {
        const html = originalLinkRenderer.call(this, href, title, text);
        const isExternal = /^https?:\/\//i.test(href);
        if (!isExternal) {
            return html;
        }
        return html.replace(/^<a /, '<a target="_blank" rel="noopener noreferrer" ');
    };
    
    marked.setOptions({
        renderer: renderer,
        breaks: true,
        gfm: true
    });
}

function setupEventListeners() {
    document.getElementById('togglePanelBtn').addEventListener('click', toggleRightPanel);

    const scrollTopBtn = document.getElementById('scrollTopBtn');
    const contentArea = document.getElementById('contentArea');
    
    // Monitor scroll on content area
    contentArea.addEventListener('scroll', () => {
        if (contentArea.scrollTop > 300) {
            scrollTopBtn.classList.add('visible');
        } else {
            scrollTopBtn.classList.remove('visible');
        }
    });

    scrollTopBtn.addEventListener('click', () => {
        contentArea.scrollTo({ top: 0, behavior: 'smooth' });
    });

    const newAssessmentBtn = document.getElementById('newAssessmentBtn');
    if (newAssessmentBtn) {
        newAssessmentBtn.addEventListener('click', resetAssessment);
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + K to focus search (if implemented later)
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            // Future: focus search input
        }
        
        // Ctrl/Cmd + R to reset
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            resetAssessment();
        }
    });
}

async function loadMarkdownFiles() {
    const mdFiles = [
        '01 - Reconnaissance & Enumeration.md',
        '02 - Vulnerability Assessment & Web Testing.md',
        '03 - Exploitation (Infrastructure & Web).md',
        '04 - Post Exploitation & Privilege Escalation.md',
        '05 - Pivoting with Ligolo-ng & Tunneling Strategy.md',
        '06 - Lateral Movement.md',
        '07 - Active Directory Exploitation.md',

    ];

    const phaseList = document.getElementById('phaseList');
    phaseList.innerHTML = '';

    let loadedCount = 0;

    for (let i = 0; i < mdFiles.length; i++) {
        const filename = "notes/"+mdFiles[i];
        
        try {
            const response = await fetch(filename);
            if (response.ok) {
                const content = await response.text();
                phases[filename] = content;
                loadedCount++;
                
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
        phaseList.innerHTML = '<div class="loading-text">⚠️ No markdown files found. Please ensure phase files are in the same directory.</div>';
        document.getElementById('contentArea').innerHTML = '<div class="loading-text">⚠️ Unable to load content. Check console for errors.</div>';
        return;
    }

    if (currentPhase && phases[currentPhase]) {
        loadPhase(currentPhase);
    } else if (Object.keys(phases).length > 0) {
        const firstPhase = Object.keys(phases)[0];
        currentPhase = firstPhase;
        loadPhase(currentPhase);
    }
}

function loadPhase(phase) {
    const content = phases[phase] || '';
    currentContent = content;
    checkboxStates.clear();
    clearCodeBlockSelection(true);
    paramSearchTerm = '';

    // Extract checkbox states from markdown
    const matches = content.matchAll(/\[([ xX])\]/g);
    let index = 0;
    for (const match of matches) {
        checkboxStates.set(index, match[1].toLowerCase() === 'x');
        index++;
    }

    // Load saved checkbox states
    const storedStates = loadCheckboxStatesFromStorage(phase);
    if (storedStates) {
        storedStates.forEach((state, idx) => {
            if (typeof state === 'boolean') {
                checkboxStates.set(idx, state);
            }
        });
    }

    extractParameters(content);
    renderContent();
    resetContentScroll();
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
        const value = getDisplayValueForParam(param);
        const regex1 = new RegExp(`<${param}>`, 'g');
        const regex2 = new RegExp(`{{${param}}}`, 'g');
        processedContent = processedContent.replace(regex1, value);
        processedContent = processedContent.replace(regex2, value);
    });

    return processedContent;
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
        wrapper.className = 'code-block';
        wrapper.dataset.blockIndex = blockIndex;
        wrapper.dataset.params = JSON.stringify(codeBlockParamMap[blockIndex] || []);
        blockIndex++;

        pre.parentNode.insertBefore(wrapper, pre);
        wrapper.appendChild(pre);

        addSelectionCopyBehavior(wrapper);
    });

    attachSelectionCopyHandler();
}

function addSelectionCopyBehavior(wrapper) {
    codeBlockWrappers.push(wrapper);
}

function attachSelectionCopyHandler() {
    if (selectionCopyHandlerAttached) {
        return;
    }

    const handleSelectionCopy = () => {
        const selection = window.getSelection();
        if (!selection || selection.isCollapsed) {
            return;
        }

        const wrapper = findIntersectingWrapper(selection);
        if (!wrapper) {
            return;
        }

        const selectedText = selection.toString();
        if (!selectedText.trim()) {
            return;
        }

        const now = Date.now();
        if (selectedText === lastCopiedSelection && wrapper === lastCopiedWrapper && (now - lastCopiedAt) < 200) {
            return;
        }

        lastCopiedSelection = selectedText;
        lastCopiedWrapper = wrapper;
        lastCopiedAt = now;

        navigator.clipboard.writeText(selectedText)
            .then(() => showCopyFeedback(wrapper, 'Copied'))
            .catch((error) => {
                console.warn('Copy failed', error);
                showCopyFeedback(wrapper, 'Copy failed');
            });
    };

    ['mouseup', 'keyup', 'touchend'].forEach(eventName => {
        document.addEventListener(eventName, handleSelectionCopy);
    });

    selectionCopyHandlerAttached = true;
}

function findIntersectingWrapper(selection) {
    if (!selection.rangeCount) {
        return null;
    }

    for (const wrapper of codeBlockWrappers) {
        if (selectionIntersectsWrapper(selection, wrapper)) {
            return wrapper;
        }
    }

    return null;
}

function selectionIntersectsWrapper(selection, wrapper) {
    for (let i = 0; i < selection.rangeCount; i++) {
        const range = selection.getRangeAt(i);
        if (typeof range.intersectsNode === 'function') {
            if (range.intersectsNode(wrapper)) {
                return true;
            }
        } else {
            const wrapperRange = document.createRange();
            wrapperRange.selectNodeContents(wrapper);
            const startsBeforeEnd = range.compareBoundaryPoints(Range.END_TO_START, wrapperRange) < 0;
            const endsAfterStart = range.compareBoundaryPoints(Range.START_TO_END, wrapperRange) > 0;
            if (startsBeforeEnd && endsAfterStart) {
                return true;
            }
        }
    }
    return false;
}

function showCopyFeedback(wrapper, message) {
    let badge = wrapper.querySelector('.copy-feedback');
    if (!badge) {
        badge = document.createElement('div');
        badge.className = 'copy-feedback';
        wrapper.appendChild(badge);
    }

    badge.textContent = message;
    badge.classList.add('visible');

    if (badge._timeoutId) {
        clearTimeout(badge._timeoutId);
    }

    badge._timeoutId = setTimeout(() => {
        badge.classList.remove('visible');
    }, 1600);
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

        const params = parseParamsFromDataset(wrapper.dataset.params);
        const targets = collectParamTargets(codeBlock, params);
        if (!targets.length) {
            return;
        }

        wrapParamsInElement(codeBlock, targets, false);
    });
}

function highlightParametersInText() {
    const contentArea = document.getElementById('contentArea');
    if (!contentArea) {
        return;
    }

    const targets = collectParamTargets(contentArea, Object.keys(parameters));
    if (!targets.length) {
        return;
    }

    wrapParamsInElement(contentArea, targets, true);
}

function collectParamTargets(element, params = []) {
    const targetSet = new Set();

    (params || []).forEach(param => {
        const value = getDisplayValueForParam(param);
        if (value) {
            targetSet.add(value);
        }
    });

    const textContent = element.textContent || '';
    const matches = textContent.match(PARAM_TOKEN_REGEX);
    if (matches && matches.length) {
        matches.forEach(token => targetSet.add(token));
    }

    return Array.from(targetSet).filter(Boolean);
}

function wrapParamsInElement(element, targets, skipCodeBlocks) {
    const regex = buildParamRegex(targets);
    if (!regex) {
        return;
    }

    const walker = document.createTreeWalker(
        element,
        NodeFilter.SHOW_TEXT,
        {
            acceptNode(node) {
                if (!node.nodeValue || !node.nodeValue.trim()) {
                    return NodeFilter.FILTER_REJECT;
                }

                const parent = node.parentElement;
                if (!parent) {
                    return NodeFilter.FILTER_ACCEPT;
                }

                if (parent.closest('.param-token')) {
                    return NodeFilter.FILTER_REJECT;
                }

                if (parent.closest('input, textarea, button, .params-panel')) {
                    return NodeFilter.FILTER_REJECT;
                }

                if (skipCodeBlocks && parent.closest('.code-block')) {
                    return NodeFilter.FILTER_REJECT;
                }

                return NodeFilter.FILTER_ACCEPT;
            }
        }
    );

    // FIX: Collect all nodes first to prevent TreeWalker index corruption
    // when nodes are replaced during the loop.
    const textNodes = [];
    let textNode;
    while ((textNode = walker.nextNode())) {
        textNodes.push(textNode);
    }

    // Process the collected nodes safely
    textNodes.forEach(node => {
        wrapMatchesInTextNode(node, regex, new Set(targets));
    });
}

function wrapMatchesInTextNode(node, regex, targetSet) {
    const text = node.nodeValue;
    regex.lastIndex = 0;

    const matches = Array.from(text.matchAll(regex));
    if (!matches.length) {
        return;
    }

    const fragment = document.createDocumentFragment();
    let lastIndex = 0;

    matches.forEach(match => {
        const start = match.index || 0;
        const value = match[0];

        if (start > lastIndex) {
            fragment.appendChild(document.createTextNode(text.slice(lastIndex, start)));
        }

        const span = document.createElement('span');
        span.className = 'param-token';
        span.textContent = value;
        fragment.appendChild(span);

        lastIndex = start + value.length;
    });

    if (lastIndex < text.length) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }

    node.parentNode.replaceChild(fragment, node);
}

function buildParamRegex(targets) {
    const escaped = targets
        .filter(Boolean)
        .map(value => escapeRegex(value))
        .sort((a, b) => b.length - a.length);

    if (!escaped.length) {
        return null;
    }

    return new RegExp(`(${escaped.join('|')})`, 'g');
}

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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
            
            // Add visual feedback
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
    const oldParams = {...parameters};
    parameters = {};
    
    const matches = extractParamsFromText(content);
    
    if (matches.length) {
        matches.forEach(param => {
            const storedValue = getStoredParameters()[param];
            parameters[param] = storedValue !== undefined ? storedValue : (oldParams[param] || '');
        });
    }
    
    renderParametersPanel();
}

function extractParamsFromText(text) {
    const matches = text.match(PARAM_TOKEN_REGEX);
    return matches ? [...new Set(matches.map(token => token.replace(/[<>{}]/g, '')))] : [];
}

function renderParametersPanel() {
    const container = document.getElementById('paramsContainer');
    const allParams = Object.keys(parameters);
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

        // Add focus animation
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
    
    // Save preference
    const isCollapsed = rightPanel.classList.contains('collapsed');
    localStorage.setItem('rightPanelCollapsed', isCollapsed);
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
        
        // Restore previous collapsed state
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

function persistParameters() {
    localStorage.setItem(PARAMS_STORAGE_KEY, JSON.stringify(parameters));
    updateResetButtonVisibility();
}

function hasStoredCheckboxData() {
    const stored = getStoredCheckboxState();
    return Object.values(stored).some(value => Array.isArray(value) && value.length > 0);
}

function hasStoredParameterData() {
    const stored = getStoredParameters();
    return Object.keys(stored).length > 0;
}

function updateResetButtonVisibility() {
    const resetBtn = document.getElementById('newAssessmentBtn');
    if (!resetBtn) {
        return;
    }

    const shouldShow = hasStoredCheckboxData() || hasStoredParameterData();
    resetBtn.hidden = !shouldShow;
}

function resetAssessment() {
    // Confirm before reset
    if (!confirm('Are you sure you want to reset the playbook? This will clear all checkboxes and parameters.')) {
        return;
    }

    localStorage.removeItem(CHECKBOX_STORAGE_KEY);
    localStorage.removeItem(PARAMS_STORAGE_KEY);
    checkboxStates.clear();
    parameters = {};
    
    if (currentPhase) {
        loadPhase(currentPhase);
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

// Add smooth transitions for better UX
document.addEventListener('DOMContentLoaded', () => {
    // Add loading animation
    document.body.style.opacity = '0';
    requestAnimationFrame(() => {
        document.body.style.transition = 'opacity 0.3s ease';
        document.body.style.opacity = '1';
    });
});
