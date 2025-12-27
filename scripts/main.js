document.addEventListener('DOMContentLoaded', () => {
    injectStyles();
    loadMarkdownFiles();
    setupEventListeners();
    setupMarkedOptions();
    updateResetButtonVisibility();
    
    document.body.style.opacity = '0';
    requestAnimationFrame(() => {
        document.body.style.transition = 'opacity 0.3s ease';
        document.body.style.opacity = '1';
    });
});

function setupEventListeners() {
    document.getElementById('togglePanelBtn').addEventListener('click', toggleRightPanel);

    const scrollTopBtn = document.getElementById('scrollTopBtn');
    const contentArea = document.getElementById('contentArea');
    
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
        newAssessmentBtn.addEventListener('click', () => {
            if (!openResetConfirmModal()) {
                resetAssessment();
            }
        });
    }

    const downloadKitBtn = document.getElementById('downloadKitBtn');
    const skeletonMenu = document.getElementById('skeletonMenu');

    if (downloadKitBtn && skeletonMenu) {
        downloadKitBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            skeletonMenu.classList.toggle('show');
        });

        skeletonMenu.querySelectorAll('.skeleton-option').forEach((option) => {
            option.addEventListener('click', (e) => {
                e.stopPropagation();
                const templateType = option.dataset.template || 'empty';
                skeletonMenu.classList.remove('show');
                downloadSkeletonZip(templateType);
            });
        });

        document.addEventListener('click', (e) => {
            if (!skeletonMenu.contains(e.target) && !downloadKitBtn.contains(e.target)) {
                skeletonMenu.classList.remove('show');
            }
        });
    }

    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            if (!openResetConfirmModal()) {
                resetAssessment();
            }
        }
    });

    setupModalTriggers();
    setupTabs();
    setupInitialParamsModal();
    setupResetConfirmModal();
    setupTransferModal();
    setupReverseShellModal();
    setupToolsTable();
    if (typeof setupGlobalSearchModal === 'function') {
        setupGlobalSearchModal();
    }
}
