import * as d3 from 'd3';
import { websocket } from '@tauri-apps/plugin-websocket';

// State
let connections = [];
let alerts = [];
let isPaused = false;
let ws = null;
let simulation = null;
let svg = null;
let g = null;
let currentView = 'graph';

// Threat level colors
const threatColors = {
    safe: '#00ff00',
    low: '#ffff00',
    medium: '#ffa500',
    high: '#ff6464',
    critical: '#ff0000'
};

function getThreatLevel(score) {
    if (score <= 25) return 'safe';
    if (score <= 49) return 'low';
    if (score <= 74) return 'medium';
    if (score <= 89) return 'high';
    return 'critical';
}

function getThreatLabel(score) {
    const level = getThreatLevel(score);
    return level.toUpperCase();
}

// Initialize the graph
function initGraph() {
    const container = document.getElementById('graph');
    const width = container.clientWidth;
    const height = container.clientHeight;
    
    svg = d3.select('#graph')
        .append('svg')
        .attr('width', '100%')
        .attr('height', '100%')
        .attr('viewBox', `0 0 ${width} ${height}`)
        .style('background', '#0d0d0d');
    
    // Add zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        });
    
    svg.call(zoom);
    
    g = svg.append('g');
    
    // Arrow markers for directed edges
    g.append('defs').append('marker')
        .attr('id', 'arrowhead')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('orient', 'auto')
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', '#666');
    
    // Initialize force simulation
    simulation = d3.forceSimulation()
        .force('link', d3.forceLink().id(d => d.id).distance(120).strength(0.5))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(40))
        .on('tick', ticked);
    
    // Handle resize
    window.addEventListener('resize', () => {
        const newWidth = container.clientWidth;
        const newHeight = container.clientHeight;
        svg.attr('viewBox', `0 0 ${newWidth} ${newHeight}`);
        simulation.force('center', d3.forceCenter(newWidth / 2, newHeight / 2));
        simulation.alpha(0.3).restart();
    });
}

// Render the graph
function renderGraph() {
    if (!simulation || !g) return;
    
    // Build nodes and links from connections
    const nodeMap = new Map();
    const linkMap = new Map();
    
    connections.forEach(conn => {
        const processId = `proc-${conn.pid}`;
        const dstId = `dst-${conn.dst_ip}`;
        
        // Process node
        if (!nodeMap.has(processId)) {
            nodeMap.set(processId, {
                id: processId,
                type: 'process',
                label: conn.process_name,
                pid: conn.pid,
                threat: getThreatLevel(conn.threat_score),
                score: conn.threat_score,
                connections: 0
            });
        }
        nodeMap.get(processId).connections++;
        
        // Destination node
        if (!nodeMap.has(dstId)) {
            nodeMap.set(dstId, {
                id: dstId,
                type: 'destination',
                label: conn.dst_ip,
                port: conn.dst_port,
                threat: 'safe',
                score: 0
            });
        }
        
        // Link
        const linkKey = `${processId}-${dstId}`;
        if (!linkMap.has(linkKey)) {
            linkMap.set(linkKey, {
                source: processId,
                target: dstId,
                protocol: conn.protocol,
                count: 0
            });
        }
        linkMap.get(linkKey).count++;
    });
    
    const nodes = Array.from(nodeMap.values());
    const links = Array.from(linkMap.values());
    
    // Update simulation
    simulation.nodes(nodes);
    simulation.force('link').links(links);
    simulation.alpha(0.3).restart();
    
    // Render links
    const link = g.selectAll('.link')
        .data(links, d => `${d.source.id}-${d.target.id}`);
    
    link.exit().remove();
    
    const linkEnter = link.enter()
        .append('line')
        .attr('class', 'link')
        .attr('stroke', '#444')
        .attr('stroke-width', d => Math.min(1 + d.count * 0.5, 5))
        .attr('marker-end', 'url(#arrowhead)')
        .attr('opacity', 0.6);
    
    link.merge(linkEnter);
    
    // Render nodes
    const node = g.selectAll('.node')
        .data(nodes, d => d.id);
    
    node.exit().remove();
    
    const nodeEnter = node.enter()
        .append('g')
        .attr('class', 'node')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));
    
    // Process nodes
    const processNodes = nodeEnter.filter(d => d.type === 'process');
    processNodes.append('circle')
        .attr('r', d => Math.max(15, Math.min(30, 10 + d.connections)))
        .attr('fill', d => threatColors[d.threat])
        .attr('stroke', '#fff')
        .attr('stroke-width', 2);
    
    processNodes.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', 4)
        .attr('font-size', '10px')
        .attr('fill', '#fff')
        .attr('font-weight', 'bold')
        .text(d => d.label.length > 12 ? d.label.substring(0, 10) + '..' : d.label);
    
    processNodes.append('title')
        .text(d => `${d.label} (PID: ${d.pid})\nThreat: ${d.threat} (${d.score})\nConnections: ${d.connections}`);
    
    // Destination nodes
    const destNodes = nodeEnter.filter(d => d.type === 'destination');
    destNodes.append('circle')
        .attr('r', 12)
        .attr('fill', '#333')
        .attr('stroke', '#666')
        .attr('stroke-width', 1);
    
    destNodes.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', 4)
        .attr('font-size', '9px')
        .attr('fill', '#aaa')
        .text(d => d.label.length > 15 ? d.label.substring(0, 13) + '..' : d.label);
    
    destNodes.append('title')
        .text(d => `${d.label}:${d.port}`);
    
    node.merge(nodeEnter);
}

function ticked() {
    if (!g) return;
    
    g.selectAll('.link')
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);
    
    g.selectAll('.node')
        .attr('transform', d => `translate(${d.x},${d.y})`);
}

function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

// Update connections table
function updateConnectionsTable() {
    const tbody = document.querySelector('#connectionsTable tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    // Show most recent first
    const recent = [...connections].reverse().slice(0, 100);
    
    recent.forEach(conn => {
        const tr = document.createElement('tr');
        const threatLevel = getThreatLevel(conn.threat_score);
        
        tr.innerHTML = `
            <td>${new Date(conn.timestamp * 1000).toLocaleTimeString()}</td>
            <td>${conn.pid}</td>
            <td>${conn.process_name}</td>
            <td>${conn.protocol}</td>
            <td>${conn.src_ip}:${conn.src_port}</td>
            <td>${conn.dst_ip}:${conn.dst_port}</td>
            <td><span class="threat-badge threat-${threatLevel}">${getThreatLabel(conn.threat_score)}</span></td>
            <td>${conn.threat_score}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Update alerts table
function updateAlertsTable() {
    const tbody = document.querySelector('#alertsTable tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    alerts.slice(0, 50).forEach(alert => {
        const tr = document.createElement('tr');
        const level = alert.threat_score >= 90 ? 'critical' : 
                      alert.threat_score >= 75 ? 'high' : 
                      alert.threat_score >= 50 ? 'medium' : 'low';
        
        tr.innerHTML = `
            <td>${new Date(alert.timestamp * 1000).toLocaleTimeString()}</td>
            <td><span class="threat-badge threat-${level}">${level.toUpperCase()}</span></td>
            <td>${alert.message}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Update alert panel
function updateAlertPanel() {
    const list = document.getElementById('alertList');
    const count = document.getElementById('alertCount');
    if (!list || !count) return;
    
    count.textContent = alerts.length;
    
    list.innerHTML = '';
    alerts.slice(0, 20).forEach(alert => {
        const level = alert.threat_score >= 90 ? 'critical' : 
                      alert.threat_score >= 75 ? 'high' : 
                      alert.threat_score >= 50 ? 'medium' : 'low';
        
        const div = document.createElement('div');
        div.className = `alert-item ${level}`;
        div.innerHTML = `
            <div>${alert.message}</div>
            <div class="alert-time">${new Date(alert.timestamp * 1000).toLocaleTimeString()}</div>
        `;
        list.appendChild(div);
    });
}

// Update statistics
function updateStats() {
    const stats = {
        total: connections.length,
        safe: 0, low: 0, medium: 0, high: 0, critical: 0
    };
    
    connections.forEach(conn => {
        const level = getThreatLevel(conn.threat_score);
        stats[level]++;
    });
    
    document.getElementById('statTotal').textContent = stats.total;
    document.getElementById('statSafe').textContent = stats.safe;
    document.getElementById('statLow').textContent = stats.low;
    document.getElementById('statMedium').textContent = stats.medium;
    document.getElementById('statHigh').textContent = stats.high;
    document.getElementById('statCritical').textContent = stats.critical;
}

// Add new connection
function addConnection(conn) {
    connections.unshift(conn);
    if (connections.length > 1000) connections.pop();
    
    if (conn.is_suspicious) {
        alerts.unshift({
            timestamp: conn.timestamp,
            threat_score: conn.threat_score,
            message: `${conn.process_name} (PID: ${conn.pid}) → ${conn.dst_ip}:${conn.dst_port} [${conn.protocol}]`
        });
        if (alerts.length > 100) alerts.pop();
    }
    
    // Update UI based on current view
    if (currentView === 'graph') renderGraph();
    else if (currentView === 'connections') updateConnectionsTable();
    else if (currentView === 'alerts') updateAlertsTable();
    else if (currentView === 'stats') updateStats();
    
    updateAlertPanel();
}

// WebSocket connection
async function connectWebSocket() {
    try {
        // Try to connect to local server
        ws = await websocket('ws://localhost:8080/ws');
        
        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleWSMessage(data);
            } catch (e) {
                console.error('WS parse error:', e);
            }
        };
        
        ws.onopen = () => {
            updateStatus(true);
            console.log('WebSocket connected');
        };
        
        ws.onclose = () => {
            updateStatus(false);
            console.log('WebSocket disconnected, retrying in 5s...');
            setTimeout(connectWebSocket, 5000);
        };
        
        ws.onerror = (err) => {
            console.error('WebSocket error:', err);
        };
    } catch (e) {
        console.error('Failed to connect WebSocket:', e);
        // Fallback to mock data for demo
        startMockData();
    }
}

function handleWSMessage(data) {
    switch (data.type) {
        case 'connection':
            addConnection(data.payload);
            break;
        case 'alert':
            alerts.unshift(data.payload);
            if (alerts.length > 100) alerts.pop();
            updateAlertPanel();
            if (currentView === 'alerts') updateAlertsTable();
            break;
        case 'stats':
            // Update stats from server
            break;
    }
}

// Mock data for demo
function startMockData() {
    const processes = ['chrome', 'firefox', 'curl', 'ssh', 'docker', 'node', 'python', 'code', 'spotify', 'discord'];
    const destinations = [
        { ip: '8.8.8.8', port: 53 }, { ip: '1.1.1.1', port: 53 },
        { ip: '192.168.1.1', port: 80 }, { ip: '10.0.0.1', port: 22 },
        { ip: '172.16.0.5', port: 443 }, { ip: '203.0.113.10', port: 8080 },
        { ip: '198.51.100.2', port: 3389 }, { ip: '10.10.10.10', port: 445 }
    ];
    const protocols = ['TCP', 'UDP'];
    
    setInterval(() => {
        if (isPaused) return;
        
        const proc = processes[Math.floor(Math.random() * processes.length)];
        const dst = destinations[Math.floor(Math.random() * destinations.length)];
        const proto = protocols[Math.floor(Math.random() * protocols.length)];
        const score = Math.floor(Math.random() * 100);
        
        const conn = {
            timestamp: Math.floor(Date.now() / 1000),
            pid: Math.floor(Math.random() * 50000) + 1000,
            process_name: proc,
            protocol: proto,
            src_ip: '192.168.1.' + Math.floor(Math.random() * 255),
            src_port: Math.floor(Math.random() * 65535),
            dst_ip: dst.ip,
            dst_port: dst.port,
            threat_score: score,
            is_suspicious: score > 50
        };
        
        addConnection(conn);
    }, 2000);
}

function updateStatus(connected) {
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    if (dot && text) {
        if (connected) {
            dot.classList.add('live');
            text.textContent = 'LIVE';
        } else {
            dot.classList.remove('live');
            text.textContent = 'DISCONNECTED';
        }
    }
}

// View switching
function switchView(view) {
    currentView = view;
    
    // Hide all views
    document.getElementById('graphView').classList.add('hidden');
    document.getElementById('connectionsView').classList.add('hidden');
    document.getElementById('alertsView').classList.add('hidden');
    document.getElementById('statsView').classList.add('hidden');
    document.getElementById('settingsView').classList.add('hidden');
    
    // Show selected view
    document.getElementById(`${view}View`).classList.remove('hidden');
    
    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.view === view);
    });
    
    // Refresh view
    if (view === 'graph') renderGraph();
    else if (view === 'connections') updateConnectionsTable();
    else if (view === 'alerts') updateAlertsTable();
    else if (view === 'stats') updateStats();
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    initGraph();
    connectWebSocket();
    
    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => switchView(item.dataset.view));
    });
    
    // Mode selector
    document.querySelectorAll('.mode-badge').forEach(badge => {
        badge.addEventListener('click', () => {
            document.querySelectorAll('.mode-badge').forEach(b => b.classList.remove('active'));
            badge.classList.add('active');
        });
    });
    
    // Toolbar
    document.getElementById('pauseBtn').addEventListener('click', (e) => {
        isPaused = !isPaused;
        e.target.textContent = isPaused ? 'Resume' : 'Pause';
    });
    
    document.getElementById('clearBtn').addEventListener('click', () => {
        connections = [];
        alerts = [];
        renderGraph();
        updateConnectionsTable();
        updateAlertsTable();
        updateStats();
        updateAlertPanel();
    });
    
    document.getElementById('filterInput').addEventListener('input', (e) => {
        // Filter connections table
        const filter = e.target.value.toLowerCase();
        document.querySelectorAll('#connectionsTable tbody tr').forEach(row => {
            row.style.display = row.textContent.toLowerCase().includes(filter) ? '' : 'none';
        });
    });
    
    document.getElementById('alertsToggleBtn').addEventListener('click', () => {
        const panel = document.getElementById('alertPanel');
        panel.classList.toggle('open');
    });
    
    document.getElementById('closeAlerts').addEventListener('click', () => {
        document.getElementById('alertPanel').classList.remove('open');
    });
    
    document.getElementById('exportBtn').addEventListener('click', () => {
        const data = { connections, alerts, timestamp: Date.now() };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nodesec-export-${new Date().toISOString()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    });
    
    // Settings
    document.getElementById('threatThreshold').addEventListener('input', (e) => {
        document.getElementById('thresholdValue').textContent = e.target.value;
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.target.tagName === 'INPUT') return;
        
        switch (e.key) {
            case ' ':
                e.preventDefault();
                isPaused = !isPaused;
                document.getElementById('pauseBtn').textContent = isPaused ? 'Resume' : 'Pause';
                break;
            case 'f':
                e.preventDefault();
                document.getElementById('filterInput').focus();
                break;
            case 'a':
                e.preventDefault();
                document.getElementById('alertPanel').classList.toggle('open');
                break;
            case 'Tab':
                if (e.shiftKey) {
                    // Handle shift+tab for reverse tab navigation
                }
                break;
            case 'q':
                // Quit would be handled by Tauri
                break;
        }
    });
});

console.log('Nodesec Network Monitor GUI loaded');