function setupModalTriggers() {
    const modalPairs = [
        { buttonId: 'fileTransferBtn', modalId: 'fileTransferModal' },
        { buttonId: 'reverseShellBtn', modalId: 'reverseShellModal' },
        { buttonId: 'toolsBtn', modalId: 'toolsModal' }
    ];

    modalPairs.forEach(({ buttonId, modalId }) => {
        const button = document.getElementById(buttonId);
        const modal = document.getElementById(modalId);

        if (!button || !modal) {
            return;
        }

        button.addEventListener('click', () => {
            resetModalState(modalId);
            hydrateModal(modalId);
            openModal(modal);
        });
    });

    document.querySelectorAll('.pwn-modal').forEach(modal => {
        modal.addEventListener('click', (event) => {
            if (event.target.closest('[data-close-modal]')) {
                closeModal(modal);
            }
        });
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeAllModals();
        }
    });
}

function setupTabs() {
    document.querySelectorAll('.modal-tabs').forEach(tabGroup => {
        const buttons = Array.from(tabGroup.querySelectorAll('[data-tab-target]'));
        if (!buttons.length) {
            return;
        }

        const container = tabGroup.closest('.pwn-modal-body') || tabGroup.parentElement;
        const panels = Array.from(container.querySelectorAll('.tab-panel'));

        const activate = (target) => {
            buttons.forEach(button => {
                button.classList.toggle('active', button.dataset.tabTarget === target);
            });

            panels.forEach(panel => {
                panel.classList.toggle('active', panel.dataset.tabPanel === target);
            });
        };

        buttons.forEach(button => {
            button.addEventListener('click', () => activate(button.dataset.tabTarget));
        });

        const activeButton = buttons.find(button => button.classList.contains('active')) || buttons[0];
        activate(activeButton.dataset.tabTarget);
    });
}

function openModal(modal) {
    if (!modal) {
        return;
    }

    closeAllModals();
    modal.classList.add('show');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');

    const focusTarget = modal.querySelector(
        '.pwn-modal-body input, .pwn-modal-body select, .pwn-modal-body textarea, .pwn-modal-body button'
    );
    if (focusTarget) {
        focusTarget.focus();
    }
}

function closeModal(modal) {
    if (!modal) {
        return;
    }

    modal.classList.remove('show');
    modal.setAttribute('aria-hidden', 'true');

    if (!document.querySelector('.pwn-modal.show')) {
        document.body.classList.remove('modal-open');
    }
}

function closeAllModals() {
    document.querySelectorAll('.pwn-modal.show').forEach(modal => closeModal(modal));
}

function openInitialParamsModal() {
    const modal = document.getElementById('initialParamsModal');
    if (!modal) {
        return;
    }

    prefillInitialParamsModal(modal);
    initialParamsPromptShown = true;
    openModal(modal);
}

function setupInitialParamsModal() {
    const modal = document.getElementById('initialParamsModal');
    if (!modal || modal.dataset.initialized === 'true') {
        return;
    }

    const lhostInput = modal.querySelector('#initialLhost');
    const rhostInput = modal.querySelector('#initialRhost');
    const saveBtn = modal.querySelector('#initialParamsSave');
    const skipBtn = modal.querySelector('#initialParamsSkip');
    const markHandledAndClose = (skip = false) => {
        if (skip) {
            markInitialParamsSkipped();
        }
        initialParamsPromptShown = true;
        closeModal(modal);
    };

    if (saveBtn) {
        saveBtn.addEventListener('click', () => {
            const lhost = (lhostInput?.value || '').trim();
            const rhost = (rhostInput?.value || '').trim();
            syncParameterValue('LHOST', lhost, { refreshPanel: true, refreshContent: true });
            syncParameterValue('RHOST', rhost, { refreshPanel: true, refreshContent: true });
            markHandledAndClose(false);
        });
    }

    if (skipBtn) {
        skipBtn.addEventListener('click', () => markHandledAndClose(true));
    }

    modal.addEventListener('click', (event) => {
        if (event.target.closest('[data-close-modal]')) {
            markHandledAndClose(true);
        }
    });

    modal.dataset.initialized = 'true';
}

function openResetConfirmModal() {
    const modal = document.getElementById('resetConfirmModal');
    if (!modal) {
        return false;
    }
    openModal(modal);
    return true;
}

function setupResetConfirmModal() {
    const modal = document.getElementById('resetConfirmModal');
    if (!modal || modal.dataset.initialized === 'true') {
        return;
    }

    const confirmBtn = modal.querySelector('#resetConfirmBtn');
    const cancelBtn = modal.querySelector('#resetCancelBtn');

    const closeAndMark = () => closeModal(modal);

    if (confirmBtn) {
        confirmBtn.addEventListener('click', () => {
            resetAssessment();
            closeAndMark();
            openInitialParamsModal();
        });
    }

    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeAndMark);
    }

    modal.addEventListener('click', (event) => {
        if (event.target.closest('[data-close-modal]')) {
            closeAndMark();
        }
    });

    modal.dataset.initialized = 'true';
}

function prefillInitialParamsModal(modal) {
    if (!modal) {
        return;
    }

    const lhostInput = modal.querySelector('#initialLhost');
    const rhostInput = modal.querySelector('#initialRhost');

    if (lhostInput) {
        lhostInput.value = (parameters?.LHOST || '').trim();
    }

    if (rhostInput) {
        rhostInput.value = (parameters?.RHOST || '').trim();
    }
}

function markInitialParamsSkipped() {
    try {
        localStorage.setItem(INITIAL_PARAMS_SKIPPED_KEY, 'true');
    } catch (error) {
        console.warn('Could not persist initial modal skip state', error);
    }
}

function hydrateModal(modalId) {
    switch (modalId) {
        case 'fileTransferModal':
            refreshTransferModalState();
            break;
        case 'reverseShellModal':
            refreshReverseModalState();
            break;
        case 'toolsModal':
            setupToolsTable();
            break;
        default:
            break;
    }
}

function resetModalState(modalId) {
    if (modalId === 'fileTransferModal') {
        const fromSelect = document.getElementById('transferFrom');
        const toSelect = document.getElementById('transferTo');
        const senderIpInput = document.getElementById('transferSenderIp');
        const senderPortInput = document.getElementById('transferSenderPort');
        const receiverIpInput = document.getElementById('transferReceiverIp');
        const senderUserInput = document.getElementById('transferSenderUser');
        const filenameInput = document.getElementById('transferFilename');
        const tbody = document.getElementById('transferTableBody');
        if (fromSelect && fromSelect.options.length) fromSelect.selectedIndex = 0;
        if (toSelect && toSelect.options.length) toSelect.selectedIndex = 0;
        if (senderIpInput) senderIpInput.value = '';
        if (senderPortInput) senderPortInput.value = '';
        if (receiverIpInput) receiverIpInput.value = '';
        if (senderUserInput) senderUserInput.value = '';
        if (filenameInput) filenameInput.value = '';
        if (tbody) tbody.innerHTML = '';
    } else if (modalId === 'reverseShellModal') {
        const modalEl = document.getElementById('reverseShellModal');
        if (modalEl) {
            modalEl.querySelectorAll('.modal-tabs').forEach(group => {
                const buttons = group.querySelectorAll('[data-tab-target]');
                const target = buttons[0]?.dataset.tabTarget;
                buttons.forEach((btn, idx) => {
                    btn.classList.toggle('active', idx === 0);
                });
                const panels = modalEl.querySelectorAll('.tab-panel');
                panels.forEach(panel => {
                    panel.classList.toggle('active', panel.dataset.tabPanel === target);
                });
            });
        }
        const lhostInput = document.getElementById('reverseLhost');
        const lportInput = document.getElementById('reverseLport');
        const typeSelect = document.getElementById('reverseType');
        const msfPayload = document.getElementById('msfvenomPayload');
        const msfOutput = document.getElementById('msfvenomOutput');
        const combinedReverse = document.getElementById('reverseCombinedCmd');
        const combinedMsf = document.getElementById('msfvenomCombinedCmd');
        const webshellSelect = document.getElementById('reverseWebType');
        const webshellContainer = document.getElementById('reverseWebshellCmd');
        if (lhostInput) lhostInput.value = '';
        if (lportInput) lportInput.value = '';
        if (typeSelect && typeSelect.options.length) typeSelect.selectedIndex = 0;
        if (msfPayload && msfPayload.options.length) msfPayload.selectedIndex = 0;
        if (msfOutput) {
            msfOutput.value = '';
            msfOutput.dataset.edited = 'false';
        }
        if (combinedReverse) combinedReverse.innerHTML = '';
        if (combinedMsf) combinedMsf.innerHTML = '';
        if (webshellSelect && webshellSelect.options.length) webshellSelect.selectedIndex = 0;
        if (webshellContainer) webshellContainer.innerHTML = '';
    } else if (modalId === 'toolsModal') {
        const toolsSearch = document.getElementById('toolsSearch');
        const wordlistsSearch = document.getElementById('wordlistsSearch');
        if (toolsSearch) toolsSearch.value = '';
        if (wordlistsSearch) wordlistsSearch.value = '';
        resetTableState('toolsTable');
        resetTableState('wordlistsTable');
    }
}

function resetTableState(tableId) {
    const table = document.getElementById(tableId);
    if (!table) return;
    const headerButtons = table.querySelectorAll('thead [data-sort-group]');
    headerButtons.forEach(btn => {
        btn.classList.remove('active');
        const icon = btn.querySelector('i');
        if (icon) icon.className = 'bi bi-chevron-expand';
    });
    if (typeof table._resetTable === 'function') {
        table._resetTable();
    }
}

function pruneModalCopyWrappers() {
    modalCopyWrappers = modalCopyWrappers.filter(wrapper => document.contains(wrapper));
}

function setupTransferModal() {
    const fromSelect = document.getElementById('transferFrom');
    const toSelect = document.getElementById('transferTo');
    const senderIpInput = document.getElementById('transferSenderIp');
    const senderPortInput = document.getElementById('transferSenderPort');
    const receiverIpInput = document.getElementById('transferReceiverIp');
    const senderUserInput = document.getElementById('transferSenderUser');
    const filenameInput = document.getElementById('transferFilename');
    const swapBtn = document.getElementById('transferSwapBtn');

    if (!fromSelect || !toSelect || !senderIpInput || !senderPortInput || !receiverIpInput || !senderUserInput || !filenameInput || !swapBtn) {
        return;
    }

    prefillTransferInputs(senderIpInput, senderPortInput, receiverIpInput, senderUserInput, filenameInput);

    const update = () => {
        const fromOs = fromSelect.value;
        const toOs = toSelect.value;
        const { senderIp, senderPort, receiverIp, senderUser, filename } = getTransferInputValues(
            senderIpInput,
            senderPortInput,
            receiverIpInput,
            senderUserInput,
            filenameInput
        );
        const changed =
            syncParameterValue('SENDER_IP', senderIp, { refreshContent: false }) ||
            syncParameterValue('SENDER_PORT', senderPort, { refreshContent: false }) ||
            syncParameterValue('RECEIVER_IP', receiverIp, { refreshContent: false }) ||
            syncParameterValue('SENDER_USER', senderUser, { refreshContent: false }) ||
            syncParameterValue('FILENAME', filename, { refreshContent: false });
        updateTransferVisual(fromOs, toOs);
        renderTransferTable(fromOs, toOs, { senderIp, senderPort, receiverIp, senderUser, filename });
        if (changed) {
            refreshContentFromParameters();
        }
    };
    fromSelect.addEventListener('change', update);
    toSelect.addEventListener('change', update);
    senderIpInput.addEventListener('input', update);
    senderPortInput.addEventListener('input', update);
    receiverIpInput.addEventListener('input', update);
    senderUserInput.addEventListener('input', update);
    filenameInput.addEventListener('input', update);
    swapBtn.addEventListener('click', () => {
        const temp = fromSelect.value;
        fromSelect.value = toSelect.value;
        toSelect.value = temp;
        update();
    });
    update();
}

function refreshTransferModalState() {
    const fromSelect = document.getElementById('transferFrom');
    const toSelect = document.getElementById('transferTo');
    const senderIpInput = document.getElementById('transferSenderIp');
    const senderPortInput = document.getElementById('transferSenderPort');
    const receiverIpInput = document.getElementById('transferReceiverIp');
    const senderUserInput = document.getElementById('transferSenderUser');
    const filenameInput = document.getElementById('transferFilename');

    if (!fromSelect || !toSelect || !senderIpInput || !senderPortInput || !receiverIpInput || !senderUserInput || !filenameInput) {
        return;
    }

    prefillTransferInputs(senderIpInput, senderPortInput, receiverIpInput, senderUserInput, filenameInput);

    const fromOs = fromSelect.value || 'linux';
    const toOs = toSelect.value || 'windows';
    const { senderIp, senderPort, receiverIp, senderUser, filename } = getTransferInputValues(
        senderIpInput,
        senderPortInput,
        receiverIpInput,
        senderUserInput,
        filenameInput
    );

    updateTransferVisual(fromOs, toOs);
    renderTransferTable(fromOs, toOs, { senderIp, senderPort, receiverIp, senderUser, filename });

    const changed =
        syncParameterValue('SENDER_IP', senderIp, { refreshContent: false }) ||
        syncParameterValue('SENDER_PORT', senderPort, { refreshContent: false }) ||
        syncParameterValue('RECEIVER_IP', receiverIp, { refreshContent: false }) ||
        syncParameterValue('SENDER_USER', senderUser, { refreshContent: false }) ||
        syncParameterValue('FILENAME', filename, { refreshContent: false });

    if (changed) {
        refreshContentFromParameters();
    }
}

function updateTransferVisual(fromOs, toOs) {
    const fromIcon = document.getElementById('transferFromIcon');
    const toIcon = document.getElementById('transferToIcon');
    const visual = document.getElementById('transferVisual');

    if (!fromIcon || !toIcon || !visual) {
        return;
    }

    fromIcon.className = `bi ${OS_ICON_MAP[fromOs] || 'bi-terminal'}`;
    toIcon.className = `bi ${OS_ICON_MAP[toOs] || 'bi-terminal'}`;

    visual.classList.remove('transfer-animate');
    void visual.offsetWidth;
    visual.classList.add('transfer-animate');
}

function renderTransferTable(fromOs, toOs, params) {
    const tbody = document.getElementById('transferTableBody');
    if (!tbody) {
        return;
    }

    tbody.innerHTML = '';
    pruneModalCopyWrappers();
    const senderIp = params?.senderIp || getStoredParamValue(['SENDER_IP', 'LHOST']);
    const senderPort = params?.senderPort || getStoredParamValue(['SENDER_PORT', 'LPORT']);
    const receiverIp = params?.receiverIp || getStoredParamValue(['RECEIVER_IP', 'RHOST']);
    const senderUser = params?.senderUser || getStoredParamValue(['SENDER_USER', 'USER']);
    const receiverUser = params?.receiverUser || getStoredParamValue('RECEIVER_USER');
    const filename = params?.filename || getStoredParamValue(['FILENAME', 'FILE']);
    const replacements = [
        { placeholder: '<SENDER_IP>', value: senderIp || '' },
        { placeholder: '<SENDER_PORT>', value: senderPort || '' },
        { placeholder: '<RECEIVER_IP>', value: receiverIp || '' },
        { placeholder: '<SENDER_USER>', value: senderUser || '' },
        { placeholder: '<RECEIVER_USER>', value: (receiverUser || senderUser || '') },
        { placeholder: '<FILENAME>', value: filename || '' },
        // Backwards compatibility
        { placeholder: '<LHOST>', value: senderIp || '' },
        { placeholder: '<LPORT>', value: senderPort || '' },
        { placeholder: '<RHOST>', value: receiverIp || '' },
        { placeholder: '<USER>', value: senderUser || '' }
    ];

    TRANSFER_PROTOCOLS.forEach(protocol => {
        const row = document.createElement('tr');

        const protocolCell = document.createElement('td');
        protocolCell.textContent = protocol.name;

        const attackerCell = buildTransferCommandCell(protocol.source[fromOs], replacements);
        const victimCell = buildTransferCommandCell(protocol.destination[toOs], replacements);

        row.appendChild(protocolCell);
        row.appendChild(attackerCell);
        row.appendChild(victimCell);
        tbody.appendChild(row);
    });

    attachSelectionCopyHandler();
}

function buildTransferCommandCell(commands, replacements) {
    const cell = document.createElement('td');

    if (!commands || commands.length === 0) {
        cell.textContent = 'No commands available for this OS.';
        return cell;
    }

    commands.forEach(item => {
        const entry = document.createElement('div');
        entry.className = 'transfer-command';

        const labelSpan = document.createElement('span');
        labelSpan.className = 'command-label';
        labelSpan.textContent = item.label;

        const snippet = createCopyableSnippet(item.command, replacements);
        snippet.classList.add('modal-code-block', 'code-block');
        addModalCopyBehavior(snippet);

        entry.appendChild(labelSpan);
        entry.appendChild(snippet);
        cell.appendChild(entry);
    });

    return cell;
}

function setupReverseShellModal() {
    const lhostInput = document.getElementById('reverseLhost');
    const lportInput = document.getElementById('reverseLport');
    const typeSelect = document.getElementById('reverseType');

    if (!lhostInput || !lportInput || !typeSelect) {
        return;
    }

    populateReverseShellOptions(typeSelect);
    populateWebshellOptions();
    prefillReverseShellInputs(lhostInput, lportInput);
    setupModalCopyZones();

    const update = () => {
        const changed =
            syncParameterValue('LHOST', lhostInput.value, { refreshContent: false }) ||
            syncParameterValue('LPORT', lportInput.value, { refreshContent: false });
        renderReverseShellCommands();
        if (changed) {
            refreshContentFromParameters();
        }
    };
    setupMsfvenomSection(update);
    lhostInput.addEventListener('input', update);
    lportInput.addEventListener('input', update);
    typeSelect.addEventListener('change', update);
    const webshellSelect = document.getElementById('reverseWebType');
    if (webshellSelect) {
        webshellSelect.addEventListener('change', () => {
            renderWebshellCommand(lhostInput.value, lportInput.value);
        });
    }
    update();
    renderWebshellCommand(lhostInput.value, lportInput.value);
}

function refreshReverseModalState() {
    const lhostInput = document.getElementById('reverseLhost');
    const lportInput = document.getElementById('reverseLport');

    if (!lhostInput || !lportInput) {
        return;
    }

    prefillReverseShellInputs(lhostInput, lportInput);

    const changed =
        syncParameterValue('LHOST', lhostInput.value, { refreshContent: false }) ||
        syncParameterValue('LPORT', lportInput.value, { refreshContent: false });

    renderReverseShellCommands();

    if (changed) {
        refreshContentFromParameters();
    }
}

function populateReverseShellOptions(select) {
    const order = ['bash', 'python', 'powershell', 'netcat'];
    select.innerHTML = '';

    order.forEach(key => {
        if (!REVERSE_SHELL_TEMPLATES[key]) {
            return;
        }
        const option = document.createElement('option');
        option.value = key;
        option.textContent = REVERSE_SHELL_TEMPLATES[key].label;
        select.appendChild(option);
    });
}

function renderReverseShellCommands() {
    const lhostInput = document.getElementById('reverseLhost');
    const lportInput = document.getElementById('reverseLport');
    const typeSelect = document.getElementById('reverseType');
    const combinedOutput = document.getElementById('reverseCombinedCmd');
    const lhostError = document.getElementById('reverseLhostError');
    const lportError = document.getElementById('reverseLportError');

    if (!lhostInput || !lportInput || !typeSelect || !combinedOutput) {
        return;
    }

    const lhost = lhostInput.value.trim();
    const lport = lportInput.value.trim();
    if (lhostError) lhostError.textContent = '';
    if (lportError) lportError.textContent = '';

    const selected = REVERSE_SHELL_TEMPLATES[typeSelect.value] || REVERSE_SHELL_TEMPLATES.bash;
    const replacements = [
        { placeholder: '{{LHOST}}', value: lhost },
        { placeholder: '{{LPORT}}', value: lport }
    ];
    const combinedTemplate = `# Victim command
${selected.victim}

# Attacker command
${selected.attacker}`;

    combinedOutput.innerHTML = '';
    const combinedSnippet = createCopyableSnippet(combinedTemplate, replacements);
    combinedOutput.appendChild(combinedSnippet);
    addModalCopyBehavior(combinedSnippet);

    renderMsfvenomCommands(lhost, lport);
    renderShellLibrarySections(lhost, lport);
    renderWebshellCommand(lhost, lport);
}

function buildLibraryReplacements(lhost, lport) {
    const stored = getStoredParameters();
    const lookup = {
        '<LHOST>': lhost || stored.LHOST || stored.lhost || '',
        '<IP>': lhost || stored.LHOST || stored.lhost || '',
        '<ATTACKER-IP>': lhost || stored.LHOST || stored.lhost || '',
        '<LPORT>': lport || stored.LPORT || stored.lport || '',
        '<PORT>': lport || stored.LPORT || stored.lport || '',
        '<ATTACKER-PORT>': lport || stored.LPORT || stored.lport || '',
        '<RHOST>': stored.RHOST || stored.rhost || '',
        '<USER>': stored.USER || stored.user || '',
        '<PASSWORD>': stored.PASSWORD || stored.password || '',
        '<FILENAME>': stored.FILENAME || stored.filename || stored.FILE || '',
        '<ATTACKER-LISTENER-IP>': lhost || stored.LHOST || stored.lhost || '',
        '<ATTACKER-LISTENER-PORT>': lport || stored.LPORT || stored.lport || ''
    };

    return Object.keys(lookup).map(key => ({ placeholder: key, value: lookup[key] }));
}

function renderShellLibrarySections(lhost, lport) {
    pruneModalCopyWrappers();
    renderShellLibrarySection('webshells', 'reverseWebshellsContent', lhost, lport);
    renderShellLibrarySection('upload-bypass', 'reverseUploadContent', lhost, lport);
    renderShellLibrarySection('stabilisation', 'reverseStabContent', lhost, lport);
}

function renderShellLibrarySection(sectionId, containerId, lhost, lport) {
    const container = document.getElementById(containerId);
    if (!container) {
        return;
    }

    const section = SHELL_LIBRARY.find(item => item.id === sectionId);
    const replacements = buildLibraryReplacements(lhost, lport);
    container.innerHTML = '';

    if (!section) {
        return;
    }

    (section.entries || []).forEach(entry => {
        const entryEl = document.createElement('div');
        entryEl.className = 'reference-entry';

        const name = document.createElement('h4');
        name.textContent = entry.name;
        if (sectionId === 'stabilisation') {
            name.classList.add('stab-heading');
        }
        entryEl.appendChild(name);

        if (entry.description) {
            const desc = document.createElement('p');
            desc.textContent = entry.description;
            entryEl.appendChild(desc);
        }

        if (entry.table && entry.table.headers && entry.table.rows) {
            const table = document.createElement('table');
            table.className = 'reference-table data-table';

            const thead = document.createElement('thead');
            const headRow = document.createElement('tr');
            entry.table.headers.forEach(text => {
                const th = document.createElement('th');
                th.textContent = text;
                headRow.appendChild(th);
            });
            thead.appendChild(headRow);
            table.appendChild(thead);

            const tbody = document.createElement('tbody');
            entry.table.rows.forEach(row => {
                const tr = document.createElement('tr');
                row.forEach((cell, idx) => {
                    const td = document.createElement('td');

                    // Upload bypass tab: render plain values (no copy buttons/snippets)
                    if (sectionId === 'upload-bypass') {
                        const headerLabel = (entry.table.headers?.[idx] || '').toLowerCase();
                        const isMagicCommand =
                            entry.name === 'Magic numbers' && headerLabel.includes('command');

                        if (isMagicCommand) {
                            const code = document.createElement('code');
                            code.innerHTML = formatTemplateWithHighlights(`${cell}`, replacements);
                            td.appendChild(code);
                        } else {
                            td.innerHTML = formatTemplateWithHighlights(`${cell}`, replacements);
                        }
                        tr.appendChild(td);
                        return;
                    }

                    // Other tabs retain copyable snippets
                    const snippet = createCopyableSnippet(`${cell}`, replacements, true);
                    td.appendChild(snippet);
                    addModalCopyBehavior(snippet);
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
            });
            table.appendChild(tbody);
            entryEl.appendChild(table);
        }

        if (entry.commands && entry.commands.length) {
            entry.commands.forEach(cmd => {
                const snippet = createCopyableSnippet(cmd, replacements);
                entryEl.appendChild(snippet);
                addModalCopyBehavior(snippet);
            });
        }

        if (entry.steps && entry.steps.length) {
            const list = document.createElement('ol');
            entry.steps.forEach(step => {
                const li = document.createElement('li');
                li.innerHTML = formatTemplateWithHighlights(step, replacements);
                list.appendChild(li);
            });
            entryEl.appendChild(list);
        }

        if (entry.bullets && entry.bullets.length) {
            const list = document.createElement('ul');
            entry.bullets.forEach(item => {
                const li = document.createElement('li');
                li.innerHTML = formatTemplateWithHighlights(item, replacements);
                list.appendChild(li);
            });
            entryEl.appendChild(list);
        }

        if (entry.codeBlocks && entry.codeBlocks.length) {
            entry.codeBlocks.forEach(block => {
                const blockWrap = document.createElement('div');
                blockWrap.className = 'code-block snippet-block';
                if (block.label) {
                    const label = document.createElement('p');
                    label.className = 'reference-code-label';
                    label.textContent = block.label;
                    blockWrap.appendChild(label);
                }
                const joined = (block.code || []).join('\n');
                const snippet = createCopyableSnippet(joined, replacements);
                const codeEl = snippet.querySelector('code');
                if (codeEl) {
                    codeEl.innerHTML = formatTemplateWithHighlights(joined, replacements);
                }
                blockWrap.appendChild(snippet);
                entryEl.appendChild(blockWrap);
                addModalCopyBehavior(snippet);
            });
        }

        if (entry.notes && entry.notes.length) {
            const notes = document.createElement('ul');
            entry.notes.forEach(note => {
                const li = document.createElement('li');
                li.textContent = note;
                notes.appendChild(li);
            });
            entryEl.appendChild(notes);
        }

        if (entry.links && entry.links.length) {
            const list = document.createElement('ul');
            entry.links.forEach(link => {
                const li = document.createElement('li');
                const a = document.createElement('a');
                a.href = link.href;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.textContent = link.label;
                li.appendChild(a);
                list.appendChild(li);
            });
            entryEl.appendChild(list);
        }

        if (entry.references && entry.references.length) {
            const refs = document.createElement('p');
            refs.className = 'reference-links';
            refs.textContent = 'References: ';
            entry.references.forEach((href, idx) => {
                const link = document.createElement('a');
                link.href = href;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.textContent = href;
                refs.appendChild(link);
                if (idx < entry.references.length - 1) {
                    refs.appendChild(document.createTextNode(' | '));
                }
            });
            entryEl.appendChild(refs);
        }

        container.appendChild(entryEl);
    });
}

function populateWebshellOptions() {
    const select = document.getElementById('reverseWebType');
    if (!select) {
        return;
    }
    const webshellSection = SHELL_LIBRARY.find(item => item.id === 'webshells');
    select.innerHTML = '';
    const entries = webshellSection?.entries || [];
    entries.forEach(entry => {
        const opt = document.createElement('option');
        opt.value = entry.name;
        opt.textContent = entry.name;
        select.appendChild(opt);
    });

    if (!select.value && entries[0]) {
        select.value = entries[0].name;
    }
}

function renderWebshellCommand(lhost, lport) {
    pruneModalCopyWrappers();
    const container = document.getElementById('reverseWebshellCmd');
    const select = document.getElementById('reverseWebType');
    if (!container || !select) {
        return;
    }

    container.classList.add('reference-content');
    const webshellSection = SHELL_LIBRARY.find(item => item.id === 'webshells');
    const entry = (webshellSection?.entries || []).find(e => e.name === select.value) || webshellSection?.entries?.[0];
    const replacements = buildLibraryReplacements(lhost, lport);

    if (!entry) {
        container.textContent = 'No webshells available.';
        return;
    }

    const snippets = entry.commands || [];
    container.innerHTML = '';
    if (!snippets.length) {
        container.textContent = 'No webshells available.';
        return;
    }

    const annotated = snippets
        .map((cmd, idx) => `# ${entry.name} ${idx + 1}\n${cmd}`)
        .join('\n\n');

    const block = createCopyableSnippet(annotated, replacements);
    block.classList.add('code-block', 'modal-code-block');
    const codeEl = block.querySelector('code');
    if (codeEl) {
        codeEl.innerHTML = formatTemplateWithHighlights(annotated, replacements);
    }
    container.appendChild(block);
    addModalCopyBehavior(block);
    attachSelectionCopyHandler();
}

function replacePlaceholders(template, replacements) {
    let output = template;
    (replacements || []).forEach(item => {
        if (!item || !item.placeholder) {
            return;
        }
        const value = item.value || item.placeholder;
        output = output.replace(new RegExp(escapeRegex(item.placeholder), 'g'), value);
    });
    return output;
}

function createCopyableSnippet(text, replacements, inline = false) {
    const wrapper = document.createElement('div');
    wrapper.className = inline ? 'copyable-snippet inline-snippet' : 'copyable-snippet';
    wrapper.setAttribute('data-copy-zone', 'true');

    const pre = document.createElement(inline ? 'code' : 'pre');
    const code = inline ? pre : document.createElement('code');
    code.innerHTML = formatTemplateWithHighlights(text, replacements);
    if (!inline) {
        pre.appendChild(code);
    }

    wrapper.appendChild(pre);
    addCopyButton(wrapper, () => code.innerText || code.textContent || '');
    return wrapper;
}

function prefillReverseShellInputs(lhostInput, lportInput) {
    const storedLhost = getStoredParamValue('LHOST');
    const storedLport = getStoredParamValue('LPORT');

    if (storedLhost) {
        lhostInput.value = storedLhost;
    }

    if (storedLport) {
        lportInput.value = storedLport;
    }
}

function getStoredParamValue(paramNames) {
    const stored = getStoredParameters();
    const names = Array.isArray(paramNames) ? paramNames : [paramNames];

    for (const name of names) {
        if (!name) {
            continue;
        }

        const direct = stored[name];
        if (direct !== undefined && `${direct}`.trim() !== '') {
            return `${direct}`.trim();
        }

        const lower = stored[name.toLowerCase()];
        if (lower !== undefined && `${lower}`.trim() !== '') {
            return `${lower}`.trim();
        }
    }

    return '';
}

function prefillTransferInputs(senderIpInput, senderPortInput, receiverIpInput, senderUserInput, filenameInput) {
    const storedSenderIp = getStoredParamValue(['SENDER_IP', 'LHOST']);
    const storedSenderPort = getStoredParamValue(['SENDER_PORT', 'LPORT']);
    const storedReceiverIp = getStoredParamValue(['RECEIVER_IP', 'RHOST']);
    const storedSenderUser = getStoredParamValue(['SENDER_USER', 'USER']);
    const storedFilename = getStoredParamValue(['FILENAME', 'FILE']);

    if (storedSenderIp) {
        senderIpInput.value = storedSenderIp;
    }

    if (storedSenderPort) {
        senderPortInput.value = storedSenderPort;
    }

    if (storedReceiverIp) {
        receiverIpInput.value = storedReceiverIp;
    }

    if (storedSenderUser) {
        senderUserInput.value = storedSenderUser;
    }

    if (storedFilename) {
        filenameInput.value = storedFilename;
    }
}

function getTransferInputValues(senderIpInput, senderPortInput, receiverIpInput, senderUserInput, filenameInput) {
    return {
        senderIp: (senderIpInput.value || '').trim(),
        senderPort: (senderPortInput.value || '').trim(),
        receiverIp: (receiverIpInput.value || '').trim(),
        senderUser: (senderUserInput.value || '').trim(),
        filename: (filenameInput.value || '').trim()
    };
}

function formatTemplateWithHighlights(template, replacements) {
    const lines = (template || '').split('\n').map(line => {
        const match = line.match(/(^|\s)#/);

        if (!match) {
            return escapeHtml(line);
        }

        const hashIndex = (match.index || 0) + match[1].length;
        const codePart = line.slice(0, hashIndex);
        const commentPart = line.slice(hashIndex);

        return `${escapeHtml(codePart)}<span class="hash-comment">${escapeHtml(commentPart)}</span>`;
    });

    let html = lines.join('\n');

    (replacements || []).forEach(item => {
        if (!item || !item.placeholder) {
            return;
        }

        const placeholder = escapeHtml(item.placeholder);
        const displayValue = item.value ? item.value : item.placeholder;
        const replacement = `<span class="param-token">${escapeHtml(displayValue)}</span>`;

        html = html.replace(new RegExp(escapeRegex(placeholder), 'g'), replacement);
    });

    return html;
}

function normalizeOutputName(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) {
        return '';
    }

    const name = trimmed.split(/[\\/]/).pop();
    return name.replace(/\.[^/.]+$/, '');
}

function buildOutputFileName(baseName, extension) {
    if (!baseName) {
        return '';
    }
    if (!extension) {
        return baseName;
    }
    return `${baseName}.${extension}`;
}

function setupMsfvenomSection(onChange) {
    const payloadSelect = document.getElementById('msfvenomPayload');
    const outputInput = document.getElementById('msfvenomOutput');

    if (!payloadSelect || !outputInput) {
        return;
    }

    payloadSelect.innerHTML = '';
    MSFVENOM_TEMPLATES.forEach(template => {
        const option = document.createElement('option');
        option.value = template.key;
        option.textContent = template.label;
        payloadSelect.appendChild(option);
    });

    const defaultTemplate = MSFVENOM_TEMPLATES[0];
    if (defaultTemplate && !outputInput.value) {
        outputInput.value = defaultTemplate.defaultName;
    }
    outputInput.dataset.edited = outputInput.value ? 'true' : 'false';

    payloadSelect.addEventListener('change', () => {
        const selected = getSelectedMsfvenomTemplate(payloadSelect.value);
        if (selected && outputInput.dataset.edited !== 'true') {
            outputInput.value = selected.defaultName;
        }
        if (typeof onChange === 'function') {
            onChange();
        }
    });

    outputInput.addEventListener('input', () => {
        outputInput.dataset.edited = outputInput.value ? 'true' : 'false';
        if (typeof onChange === 'function') {
            onChange();
        }
    });
}

function getSelectedMsfvenomTemplate(selectedKey) {
    return MSFVENOM_TEMPLATES.find(template => template.key === selectedKey) || MSFVENOM_TEMPLATES[0];
}

function renderMsfvenomCommands(lhost, lport) {
    const payloadSelect = document.getElementById('msfvenomPayload');
    const outputInput = document.getElementById('msfvenomOutput');
    const combinedOutput = document.getElementById('msfvenomCombinedCmd');

    if (!payloadSelect || !outputInput || !combinedOutput) {
        return;
    }

    const selected = getSelectedMsfvenomTemplate(payloadSelect.value);
    const baseName = normalizeOutputName(outputInput.value) || selected.defaultName;
    const outputFile = buildOutputFileName(baseName, selected.extension);

    const payload = selected.payload;
    const format = selected.format;
    const replacements = [
        { placeholder: '{{LHOST}}', value: lhost },
        { placeholder: '{{LPORT}}', value: lport },
        { placeholder: '{{OUTPUT}}', value: outputFile }
    ];

    const msfvenomTemplate = `msfvenom -p ${payload} LHOST={{LHOST}} LPORT={{LPORT}} -f ${format} -o {{OUTPUT}}`;
    const listenerTemplate = `msfconsole -q -x "use exploit/multi/handler; set payload ${payload}; set LHOST {{LHOST}}; set LPORT {{LPORT}}; run -j"`;

    const combinedTemplate = `# msfvenom
${msfvenomTemplate}

# Listener
${listenerTemplate}`;

    combinedOutput.innerHTML = '';
    const snippet = createCopyableSnippet(combinedTemplate, replacements);
    combinedOutput.appendChild(snippet);
    addModalCopyBehavior(snippet);
}

function setupModalCopyZones() {
    const zones = document.querySelectorAll('[data-copy-zone]');
    modalCopyWrappers = [];

    zones.forEach(zone => addModalCopyBehavior(zone));
    attachSelectionCopyHandler();
}

function setupToolsTable() {
    const toolMap = new Map();

    (TOOLBOX_ITEMS || []).forEach(tool => {
        const name = (tool.name || '').trim();
        const key = name.toLowerCase();
        if (!key) {
            return;
        }

        if (!toolMap.has(key)) {
            toolMap.set(key, {
                name,
                categories: [],
                installationLines: [],
                link: tool.link || '',
                linkLabel: tool.linkLabel || ''
            });
        }

        const entry = toolMap.get(key);
        if (tool.category && !entry.categories.includes(tool.category)) {
            entry.categories.push(tool.category);
        }
        if (Array.isArray(tool.installation)) {
            tool.installation
                .map(line => line.trim())
                .filter(Boolean)
                .forEach(line => {
                    if (!entry.installationLines.includes(line)) {
                        entry.installationLines.push(line);
                    }
                });
        }
        if (!entry.link && tool.link) {
            entry.link = tool.link;
            entry.linkLabel = tool.linkLabel || entry.linkLabel;
        }
    });

    const toolRows = Array.from(toolMap.values()).map(entry => ({
        name: entry.name,
        category: entry.categories.join(' / '),
        installation: entry.installationLines.join('\n'),
        linkHtml: entry.link ? `<a href="${escapeHtml(entry.link)}" target="_blank" rel="noopener noreferrer">${escapeHtml(entry.linkLabel || 'Link')}</a>` : ''
    }));

    const wordlistRows = (WORDLISTS || []).map(list => ({
        name: list.name,
        category: list.category,
        command: list.command || ''
    }));

    const passwordCrackingRows = (PASSWORD_CRACKING || []).map(item => ({
        tool: item.tool,
        useCase: item.useCase,
        command: item.command || ''
    }));

    setupFilterableTable({
        tableId: 'toolsTable',
        searchInputId: 'toolsSearch',
        sortGroup: 'tools',
        columns: [
            { key: 'name', index: 0 },
            { key: 'category', index: 1 },
            {
                key: 'installation',
                index: 2,
                render: (value) => {
                    if (!value) {
                        return document.createTextNode('');
                    }
                    const snippet = createCopyableSnippet(value, [], true);
                    snippet.classList.add('table-snippet');
                    addModalCopyBehavior(snippet);
                    return snippet;
                }
            }
        ],
        searchKeys: ['name', 'category'],
        emptyMessage: 'No tools match your search.',
        data: toolRows
    });

    setupFilterableTable({
        tableId: 'wordlistsTable',
        searchInputId: 'wordlistsSearch',
        sortGroup: 'wordlists',
        columns: [
            { key: 'name', index: 0 },
            { key: 'category', index: 1 },
            {
                key: 'command',
                index: 2,
                render: (value) => {
                    if (!value) {
                        return document.createTextNode('');
                    }
                    const snippet = createCopyableSnippet(value, [], true);
                    snippet.classList.add('table-snippet');
                    addModalCopyBehavior(snippet);
                    return snippet;
                }
            }
        ],
        searchKeys: ['name', 'category', 'command'],
        emptyMessage: 'No wordlists match your search.',
        data: wordlistRows
    });

    setupFilterableTable({
        tableId: 'passwordCrackingTable',
        searchInputId: 'passwordCrackingSearch',
        sortGroup: 'password-cracking',
        columns: [
            { key: 'tool', index: 0 },
            { key: 'useCase', index: 1 },
            {
                key: 'command',
                index: 2,
                render: (value) => {
                    if (!value) {
                        return document.createTextNode('');
                    }
                    const snippet = createCopyableSnippet(value, [], true);
                    snippet.classList.add('table-snippet');
                    addModalCopyBehavior(snippet);
                    return snippet;
                }
            }
        ],
        searchKeys: ['tool', 'useCase', 'command'],
        emptyMessage: 'No password cracking commands match your search.',
        data: passwordCrackingRows
    });
}

function setupFilterableTable(config) {
    const table = document.getElementById(config.tableId);
    const searchInput = document.getElementById(config.searchInputId);
    const headerButtons = table ? table.querySelectorAll(`thead [data-sort-group="${config.sortGroup}"]`) : [];

    if (!table || !searchInput || !headerButtons.length) {
        return;
    }

    const tbody = table.querySelector('tbody');
    if (!tbody) {
        return;
    }

    const rowsData = (config.data && config.data.length)
        ? config.data.map(row => ({ ...row }))
        : Array.from(tbody.querySelectorAll('tr')).map(row => {
              const cells = row.querySelectorAll('td');
              const record = {};
              config.columns.forEach(column => {
                  const cell = cells[column.index];
                  if (!cell) {
                      record[column.key] = '';
                      return;
                  }
                  record[column.key] = column.html ? cell.innerHTML.trim() : cell.textContent.trim();
              });
              return record;
          });

    const state = {
        sortKey: config.columns[0]?.key || 'name',
        sortAsc: true
    };

    const render = () => {
        pruneModalCopyWrappers();
        const term = searchInput.value.trim().toLowerCase();
        const filtered = rowsData.filter(row => {
            if (!term) {
                return true;
            }

            return config.searchKeys.some(key => (row[key] || '').toLowerCase().includes(term));
        });

        const sorted = filtered.sort((a, b) => {
            const aVal = (a[state.sortKey] || '').toLowerCase();
            const bVal = (b[state.sortKey] || '').toLowerCase();
            return state.sortAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
        });

        tbody.innerHTML = '';

        if (!sorted.length) {
            const emptyRow = document.createElement('tr');
            const emptyCell = document.createElement('td');
            emptyCell.colSpan = config.columns.length;
            emptyCell.className = 'tools-empty';
            emptyCell.textContent = config.emptyMessage || 'No results found.';
            emptyRow.appendChild(emptyCell);
            tbody.appendChild(emptyRow);
            return;
        }

        sorted.forEach(rowData => {
            const row = document.createElement('tr');
            config.columns.forEach(column => {
                const cell = document.createElement('td');
                const value = rowData[column.key];
                if (typeof column.render === 'function') {
                    const rendered = column.render(value, rowData, cell);
                    if (rendered instanceof Node) {
                        cell.appendChild(rendered);
                    } else if (column.html) {
                        cell.innerHTML = rendered || '';
                    } else {
                        cell.textContent = rendered || '';
                    }
                } else if (column.html) {
                    cell.innerHTML = value || '';
                } else {
                    cell.textContent = value || '';
                }
                row.appendChild(cell);
            });
            tbody.appendChild(row);
        });
        attachSelectionCopyHandler();
    };

    headerButtons.forEach(button => {
        if (button.dataset.bound === 'true') {
            return;
        }
        button.dataset.bound = 'true';
        button.addEventListener('click', () => {
            const key = button.dataset.sortKey || state.sortKey;
            if (state.sortKey === key) {
                state.sortAsc = !state.sortAsc;
            } else {
                state.sortKey = key;
                state.sortAsc = true;
            }
            headerButtons.forEach(btn => {
                const icon = btn.querySelector('i');
                if (btn.dataset.sortKey === state.sortKey) {
                    btn.classList.add('active');
                    if (icon) {
                        icon.className = state.sortAsc ? 'bi bi-chevron-up' : 'bi bi-chevron-down';
                    }
                } else {
                    btn.classList.remove('active');
                    if (icon) {
                        icon.className = 'bi bi-chevron-expand';
                    }
                }
            });
            render();
        });
    });

    table._resetTable = () => {
        state.sortKey = config.columns[0]?.key || 'name';
        state.sortAsc = true;
        searchInput.value = '';
        headerButtons.forEach(btn => {
            btn.classList.remove('active');
            const icon = btn.querySelector('i');
            if (icon) icon.className = 'bi bi-chevron-expand';
        });
        render();
    };

    render();
    searchInput.addEventListener('input', render);
}

async function downloadSkeletonZip(templateType = 'empty') {
    const downloadBtn = document.getElementById('downloadKitBtn');
    if (!downloadBtn || typeof JSZip === 'undefined') {
        console.error('JSZip is not available; cannot build the notes kit.');
        return;
    }

    const originalLabel = downloadBtn.innerHTML;
    downloadBtn.disabled = true;
    downloadBtn.innerHTML = '<i class="bi bi-hourglass-split" aria-hidden="true"></i><span>Building kit...</span>';

    try {
        const zip = new JSZip();
        const basePath = 'pwnsheet-skeleton/';
        const skeletonFiles = await buildNotesSkeleton(templateType);

        if (!skeletonFiles || Object.keys(skeletonFiles).length === 0) {
            throw new Error('No skeleton files loaded for template: ' + templateType);
        }

        Object.entries(skeletonFiles).forEach(([path, content]) => {
            const normalizedContent = content.startsWith('\n') ? content.slice(1) : content;
            zip.file(basePath + path, normalizedContent);
        });

        const blob = await zip.generateAsync({ type: 'blob' });
        const downloadLink = document.createElement('a');
        downloadLink.href = URL.createObjectURL(blob);
        downloadLink.download = `pwnsheet-skeleton-${templateType}.zip`;
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        setTimeout(() => URL.revokeObjectURL(downloadLink.href), 1200);
    } catch (error) {
        console.error('Failed to build the notes kit zip', error);
    } finally {
        downloadBtn.disabled = false;
        downloadBtn.innerHTML = originalLabel;
    }
}

async function buildNotesSkeleton(templateType = 'empty') {
    const templateDir = `skeleton/${templateType}`;
    const manifestUrl = `${templateDir}/manifest.json`;

    try {
        const manifestResponse = await fetch(manifestUrl);
        if (!manifestResponse.ok) {
            throw new Error(`Manifest not found for template: ${templateType}`);
        }

        const manifest = await manifestResponse.json();

        const fileEntries = await Promise.all(manifest.map(async (relativePath) => {
            const fileResponse = await fetch(`${templateDir}/${relativePath}`);
            if (!fileResponse.ok) {
                throw new Error(`Failed to load skeleton file: ${relativePath}`);
            }

            const content = await fileResponse.text();
            return [relativePath, content];
        }));

        return Object.fromEntries(fileEntries);
    } catch (error) {
        console.error('Failed to load skeleton templates:', error);
        return {};
    }
}
