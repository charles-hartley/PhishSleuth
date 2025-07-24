document.addEventListener('DOMContentLoaded', function() {
    // Initialize the application
    initializeApp();
});

// Global variables
let currentScanId = null;
let isScanning = false;
let matrixInterval = null;
let terminalInterval = null;
let statsInterval = null;

// Initialize application
function initializeApp() {
    console.log('PhishSleuth Elite Edition v2.1.0 - Initializing...');
    
    // Initialize components
    initializeMatrixBackground();
    initializeTerminalDemo();
    initializeTabs();
    initializeFormHandlers();
    initializeScrollEffects();
    initializeStatsUpdater();
    initializeTooltips();
    
    // Load initial data
    loadStatistics();
    loadHistory();
    
    console.log('PhishSleuth ready for deployment');
}

// Matrix background animation
function initializeMatrixBackground() {
    const matrixContainer = document.getElementById('matrixRain');
    if (!matrixContainer) return;
    
    const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
    const columns = Math.floor(window.innerWidth / 20);
    const drops = Array(columns).fill(1);
    
    function drawMatrix() {
        matrixContainer.innerHTML = '';
        
        for (let i = 0; i < columns; i++) {
            const drop = document.createElement('div');
            drop.className = 'matrix-char';
            drop.style.left = i * 20 + 'px';
            drop.style.top = drops[i] * 20 + 'px';
            drop.textContent = chars[Math.floor(Math.random() * chars.length)];
            drop.style.color = `hsl(${120 + Math.random() * 60}, 70%, ${50 + Math.random() * 30}%)`;
            matrixContainer.appendChild(drop);
            
            if (drops[i] * 20 > window.innerHeight && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    
    matrixInterval = setInterval(drawMatrix, 100);
}

// Terminal demo animation
function initializeTerminalDemo() {
    const terminal = document.getElementById('demoTerminal');
    if (!terminal) return;
    
    const messages = [
        '[root@phishsleuth ~]# Initializing threat detection modules...',
        '[INFO] Loading NLP models... [OK]',
        '[INFO] Scanning for malicious patterns... [PROCESSING]',
        '[INFO] Cross-referencing threat database... [RUNNING]',
        '[SUCCESS] Neural network ready for deployment',
        '[SCAN] Real-time threat monitoring active',
        '[BLOCK] Prevented 247 phishing attempts in last hour',
        '[STATUS] All systems operational - 99.97% uptime'
    ];
    
    let messageIndex = 0;
    
    function addTerminalMessage() {
        if (messageIndex < messages.length) {
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.textContent = messages[messageIndex];
            terminal.appendChild(line);
            messageIndex++;
            
            // Remove old messages to keep terminal clean
            if (terminal.children.length > 8) {
                terminal.removeChild(terminal.firstChild);
            }
        } else {
            messageIndex = 0;
            terminal.innerHTML = '';
        }
    }
    
    terminalInterval = setInterval(addTerminalMessage, 2000);
}

// Tab system initialization
function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all tabs
            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            // Add active class to clicked tab
            btn.classList.add('active');
            const tabId = btn.dataset.tab + '-tab';
            document.getElementById(tabId).classList.add('active');
            
            // Update form action based on tab
            updateFormAction(btn.dataset.tab);
        });
    });
}

// Update form action based on selected tab
function updateFormAction(tabType) {
    const form = document.getElementById('analysisForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    switch(tabType) {
        case 'text':
            form.dataset.action = 'text';
            analyzeBtn.innerHTML = '<i class="fas fa-search me-2"></i>ANALYZE TEXT';
            break;
        case 'file':
            form.dataset.action = 'file';
            analyzeBtn.innerHTML = '<i class="fas fa-file-search me-2"></i>ANALYZE FILE';
            break;
        case 'url':
            form.dataset.action = 'url';
            analyzeBtn.innerHTML = '<i class="fas fa-link me-2"></i>SCAN URL';
            break;
    }
}

// Form handlers initialization
function initializeFormHandlers() {
    const form = document.getElementById('analysisForm');
    const fileInput = document.getElementById('emailFile');
    
    if (form) {
        form.addEventListener('submit', handleFormSubmit);
        form.dataset.action = 'text'; // Default action
    }
    
    // File upload handler
    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelection);
    }
    
    // File drag and drop
    const fileUpload = document.querySelector('.file-upload');
    if (fileUpload) {
        fileUpload.addEventListener('dragover', handleDragOver);
        fileUpload.addEventListener('drop', handleFileDrop);
    }
}

// Handle form submission
async function handleFormSubmit(e) {
    e.preventDefault();
    
    if (isScanning) {
        showNotification('Analysis already in progress', 'warning');
        return;
    }
    
    const formData = new FormData(e.target);
    const actionType = e.target.dataset.action || 'text';
    
    try {
        isScanning = true;
        showLoadingSection();
        
        let response;
        switch(actionType) {
            case 'text':
                response = await analyzeText(formData);
                break;
            case 'file':
                response = await analyzeFile(formData);
                break;
            case 'url':
                response = await analyzeUrl(formData);
                break;
            default:
                throw new Error('Invalid analysis type');
        }
        
        if (response.success) {
            displayResults(response);
            loadHistory(); // Refresh history
            loadStatistics(); // Update stats
        } else {
            showNotification(response.error || 'Analysis failed', 'error');
        }
        
    } catch (error) {
        console.error('Analysis error:', error);
        showNotification('Analysis failed: ' + error.message, 'error');
    } finally {
        isScanning = false;
        hideLoadingSection();
    }
}

// Text analysis
async function analyzeText(formData) {
    const data = {
        emailSubject: formData.get('emailSubject') || '',
        emailBody: formData.get('emailBody') || ''
    };
    
    if (!data.emailSubject && !data.emailBody) {
        throw new Error('Please provide email subject or body content');
    }
    
    const response = await fetch(window.djangoData.urls.analyzeText, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': window.djangoData.csrfToken
        },
        body: JSON.stringify(data)
    });
    
    return await response.json();
}

// File analysis
async function analyzeFile(formData) {
    const file = formData.get('emailFile');
    
    if (!file || file.size === 0) {
        throw new Error('Please select a file to analyze');
    }
    
    // Validate file type
    const allowedTypes = ['.eml', '.msg', '.txt'];
    const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    
    if (!allowedTypes.includes(fileExtension)) {
        throw new Error('Unsupported file type. Please use .eml, .msg, or .txt files');
    }
    
    const response = await fetch(window.djangoData.urls.analyzeFile, {
        method: 'POST',
        headers: {
            'X-CSRFToken': window.djangoData.csrfToken
        },
        body: formData
    });
    
    return await response.json();
}

// URL analysis
async function analyzeUrl(formData) {
    const data = {
        urlInput: formData.get('urlInput') || ''
    };
    
    if (!data.urlInput) {
        throw new Error('Please provide a URL to analyze');
    }
    
    // Basic URL validation
    try {
        new URL(data.urlInput);
    } catch {
        throw new Error('Please provide a valid URL');
    }
    
    const response = await fetch(window.djangoData.urls.analyzeUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': window.djangoData.csrfToken
        },
        body: JSON.stringify(data)
    });
    
    return await response.json();
}

// File selection handler
function handleFileSelection(e) {
    const file = e.target.files[0];
    if (file) {
        const label = document.querySelector('.file-upload-label');
        label.innerHTML = `
            <i class="fas fa-file-alt fa-2x mb-2"></i>
            <div>Selected: ${file.name}</div>
            <small class="text-muted">${(file.size / 1024).toFixed(1)} KB</small>
        `;
        label.classList.add('file-selected');
    }
}

// Drag and drop handlers
function handleDragOver(e) {
    e.preventDefault();
    e.currentTarget.classList.add('drag-over');
}

function handleFileDrop(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        document.getElementById('emailFile').files = files;
        handleFileSelection({ target: { files: files } });
    }
}

// Show loading section
function showLoadingSection() {
    document.getElementById('scanner').style.display = 'none';
    document.getElementById('results').style.display = 'none';
    document.getElementById('loadingSection').style.display = 'block';
    
    // Animate loading terminal
    animateLoadingTerminal();
}

// Hide loading section
function hideLoadingSection() {
    document.getElementById('loadingSection').style.display = 'none';
    document.getElementById('scanner').style.display = 'block';
}

// Animate loading terminal
function animateLoadingTerminal() {
    const terminal = document.querySelector('#loadingSection .terminal-output');
    if (!terminal) return;
    
    const lines = terminal.querySelectorAll('.terminal-line');
    lines.forEach((line, index) => {
        setTimeout(() => {
            line.style.opacity = '1';
            line.style.transform = 'translateX(0)';
        }, index * 500);
    });
}

// Display analysis results
function displayResults(data) {
    currentScanId = data.scan_id;
    
    // Update threat score and status
    const threatScore = Math.round(data.threat_score * 100);
    const threatLevel = getThreatLevel(threatScore);
    
    document.getElementById('threatScore').textContent = threatScore + '%';
    document.getElementById('threatProgress').style.width = threatScore + '%';
    document.getElementById('threatProgress').textContent = threatScore + '%';
    document.getElementById('threatProgress').className = `progress-bar ${getThreatColor(threatScore)}`;
    
    // Update confidence
    const confidence = Math.round(data.confidence * 100);
    document.getElementById('confidenceProgress').style.width = confidence + '%';
    document.getElementById('confidenceProgress').textContent = confidence + '%';
    
    // Update threat status
    const statusElement = document.getElementById('threatStatus');
    statusElement.innerHTML = `
        <i class="fas ${getThreatIcon(threatScore)}"></i>
        ${threatLevel}
    `;
    statusElement.className = getThreatTextColor(threatScore);
    
    // Update highlighted content
    const highlightedContent = document.getElementById('highlightedContent');
    if (data.highlighted_content) {
        highlightedContent.innerHTML = data.highlighted_content;
    } else {
        highlightedContent.innerHTML = '<p>No content highlights available</p>';
    }
    
    // Update detected threats
    updateDetectedThreats(data.threats || []);
    
    // Update recommendations
    updateRecommendations(data.recommendations || []);
    
    // Show results section
    document.getElementById('results').style.display = 'block';
    
    // Scroll to results
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

// Update detected threats
function updateDetectedThreats(threats) {
    const container = document.getElementById('detectedThreats');
    
    if (threats.length === 0) {
        container.innerHTML = '<p class="text-muted">No specific threats detected</p>';
        return;
    }
    
    container.innerHTML = threats.map(threat => `
        <div class="d-flex justify-content-between align-items-center mb-2">
            <span>
                <i class="fas ${threat.icon || 'fa-exclamation-triangle'} text-${threat.color || 'warning'}"></i>
                ${threat.name}
            </span>
            <span class="badge bg-${threat.color || 'warning'}">${threat.severity || 'Medium'}</span>
        </div>
    `).join('');
}

// Update recommendations
function updateRecommendations(recommendations) {
    const container = document.getElementById('recommendedActions');
    
    if (recommendations.length === 0) {
        container.innerHTML = '<li class="text-muted">No specific recommendations available</li>';
        return;
    }
    
    container.innerHTML = recommendations.map(rec => `
        <li class="mb-2">
            <i class="fas ${rec.icon || 'fa-info-circle'} text-${rec.color || 'info'}"></i>
            ${rec.text}
        </li>
    `).join('');
}

// Get threat level based on score
function getThreatLevel(score) {
    if (score >= 70) return 'HIGH RISK DETECTED';
    if (score >= 40) return 'MEDIUM RISK DETECTED';
    return 'LOW RISK DETECTED';
}

// Get threat color class
function getThreatColor(score) {
    if (score >= 70) return 'bg-danger';
    if (score >= 40) return 'bg-warning';
    return 'bg-success';
}

// Get threat text color
function getThreatTextColor(score) {
    if (score >= 70) return 'text-danger';
    if (score >= 40) return 'text-warning';
    return 'text-success';
}

// Get threat icon
function getThreatIcon(score) {
    if (score >= 70) return 'fa-exclamation-triangle';
    if (score >= 40) return 'fa-exclamation-circle';
    return 'fa-check-circle';
}

// Load statistics
async function loadStatistics() {
    try {
        const response = await fetch(window.djangoData.urls.getStatistics);
        const data = await response.json();
        
        if (data.success) {
            updateStatistics(data.stats);
        }
    } catch (error) {
        console.error('Failed to load statistics:', error);
    }
}

// Update statistics display
function updateStatistics(stats) {
    const elements = {
        emailsAnalyzed: document.getElementById('emailsAnalyzed'),
        threatsBlocked: document.getElementById('threatsBlocked'),
        accuracyRate: document.getElementById('accuracyRate'),
        activeUsers: document.getElementById('activeUsers')
    };
    
    if (elements.emailsAnalyzed) elements.emailsAnalyzed.textContent = formatNumber(stats.total_scans);
    if (elements.threatsBlocked) elements.threatsBlocked.textContent = formatNumber(stats.threats_blocked);
    if (elements.accuracyRate) elements.accuracyRate.textContent = stats.accuracy_rate;
    if (elements.activeUsers) elements.activeUsers.textContent = formatNumber(stats.active_users);
}

// Load scan history
async function loadHistory() {
    try {
        const response = await fetch(window.djangoData.urls.getHistory);
        const data = await response.json();
        
        if (data.success) {
            updateHistoryTable(data.scans);
        }
    } catch (error) {
        console.error('Failed to load history:', error);
    }
}

// Update history table
function updateHistoryTable(scans) {
    const tbody = document.getElementById('historyTableBody');
    if (!tbody) return;
    
    if (scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No recent scans available</td></tr>';
        return;
    }
    
    tbody.innerHTML = scans.map(scan => `
        <tr>
            <td>${scan.timestamp}</td>
            <td>${scan.source}</td>
            <td>
                <span class="badge ${getThreatBadgeClass(scan.threat_level)}">
                    ${Math.round(scan.confidence * 100)}%
                </span>
            </td>
            <td>
                <span class="status-indicator ${scan.is_phishing ? 'status-danger' : 'status-safe'}"></span>
                ${scan.is_phishing ? 'Blocked' : 'Safe'}
            </td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="viewScanDetails('${scan.id}')">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

// Get badge class for threat level
function getThreatBadgeClass(threatLevel) {
    switch(threatLevel) {
        case 'HIGH': return 'bg-danger';
        case 'MEDIUM': return 'bg-warning';
        case 'LOW': return 'bg-success';
        default: return 'bg-secondary';
    }
}

// View scan details
async function viewScanDetails(scanId) {
    try {
        const response = await fetch(`/api/scan/${scanId}/`);
        const data = await response.json();
        
        if (data.success) {
            displayScanDetails(data);
        } else {
            showNotification('Failed to load scan details', 'error');
        }
    } catch (error) {
        console.error('Failed to load scan details:', error);
        showNotification('Failed to load scan details', 'error');
    }
}

// Display scan details in modal or section
function displayScanDetails(scanData) {
    // This would typically show in a modal
    // For now, we'll just log the data and show a notification
    console.log('Scan details:', scanData);
    showNotification('Scan details loaded (check console)', 'info');
}

// Download report
function downloadReport() {
    if (!currentScanId) {
        showNotification('No scan selected for report download', 'warning');
        return;
    }
    
    const url = getDownloadReportUrl(currentScanId);
    const link = document.createElement('a');
    link.href = url;
    link.download = `phishsleuth_report_${currentScanId}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    showNotification('Report download initiated', 'success');
}

// Initialize scroll effects
function initializeScrollEffects() {
    const navbar = document.querySelector('.navbar');
    
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });
}

// Initialize stats updater
function initializeStatsUpdater() {
    // Update stats every 30 seconds
    statsInterval = setInterval(() => {
        loadStatistics();
    }, 30000);
}

// Initialize tooltips
function initializeTooltips() {
    // Add tooltips to various elements
    const tooltipElements = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipElements.forEach(element => {
        new bootstrap.Tooltip(element);
    });
}

// Utility functions
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

// Notification system
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show notification`;
    notification.innerHTML = `
        <i class="fas fa-${getNotificationIcon(type)} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 5000);
}

// Get notification icon
function getNotificationIcon(type) {
    switch(type) {
        case 'success': return 'check-circle';
        case 'error': case 'danger': return 'exclamation-triangle';
        case 'warning': return 'exclamation-circle';
        default: return 'info-circle';
    }
}

// Navigation functions
function scrollToScanner() {
    document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
}

function scrollToTop() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showDemo() {
    showNotification('Demo mode activated - Try analyzing the sample text!', 'info');
    
    // Fill in demo data
    const activeTab = document.querySelector('.tab-btn.active').dataset.tab;
    
    if (activeTab === 'text') {
        document.getElementById('emailSubject').value = 'URGENT: Your account will be suspended!';
        document.getElementById('emailBody').value = `Dear Customer,

Your account has been compromised and will be suspended in 24 hours unless you verify your information immediately.

Click here to verify: http://suspicious-link.com/verify

Best regards,
Amazon Security Team`;
    } else if (activeTab === 'url') {
        document.getElementById('urlInput').value = 'http://suspicious-amazon-verify.com/login';
    }
}

// Cleanup function
function cleanup() {
    if (matrixInterval) clearInterval(matrixInterval);
    if (terminalInterval) clearInterval(terminalInterval);
    if (statsInterval) clearInterval(statsInterval);
}

// Handle page unload
window.addEventListener('beforeunload', cleanup);

// Export functions for global access
window.scrollToScanner = scrollToScanner;
window.scrollToTop = scrollToTop;
window.showDemo = showDemo;
window.downloadReport = downloadReport;
window.viewScanDetails = viewScanDetails;
window.showNotification = showNotification;