import React, { useState, useEffect } from 'react';
import { useWebSocket } from './hooks/useWebSocket';
import Radar from './components/Radar';
import AgentsTable from './components/AgentsTable';
import ForceGraph from './components/ForceGraph';
import { CommandHeader } from './components/CommandHeader';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, ArcElement, Tooltip, Legend } from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, ArcElement, Tooltip, Legend);

const chartOptions = {
    responsive: true, maintainAspectRatio: false, animation: false,
    plugins: { legend: { display: false } },
    scales: {
        x: { display: false },
        y: { grid: { color: '#2A303F' }, ticks: { color: '#94A3B8' }, suggestedMin: 0 }
    }
};

function App() {
    const { data, connectionState } = useWebSocket();
    const [timeLabels, setTimeLabels] = useState([]);
    const [ramData, setRamData] = useState([]);
    const [cpuData, setCpuData] = useState([]);

    const activeNodes = data.active_nodes || [];
    const logs = data.logs || [];
    
    const agentCount = activeNodes.length;
    const compCount = activeNodes.filter(n => n.status === 'COMPROMIS' || n.status === 'DISCONNECTED_ALERT' || n.status === 'SELF_ISOLATED').length;
    const stableCount = agentCount === 0 ? 0 : agentCount - compCount; 
    
    const totalRam = activeNodes.reduce((acc, curr) => acc + (curr.ram_mb || 0), 0);
    const avgRam = agentCount > 0 ? Math.round(totalRam / agentCount) : 0;
    
    const totalCpu = activeNodes.reduce((acc, curr) => acc + ((curr.cpu_load || 0) / (curr.procs || 1)), 0);
    const avgCpu = agentCount > 0 ? (totalCpu / agentCount) : 0;

    useEffect(() => {
        if (agentCount > 0) {
            const now = new Date().toLocaleTimeString('fr-FR', { hour12: false });
            setTimeLabels(prev => [...prev.slice(-24), now]);
            setRamData(prev => [...prev.slice(-24), avgRam]);
            setCpuData(prev => [...prev.slice(-24), avgCpu * 100]); 
        }
    }, [agentCount, avgRam, avgCpu]);

    // ARCHITECTURAL FIX: Dynamic Edge Severing
    const isolatedSet = new Set(activeNodes.filter(n => n.status === 'COMPROMIS').map(n => n.id));
    
    const edges = [];
    activeNodes.forEach(node => {
        if (node.neighbors && !isolatedSet.has(node.id)) {
            node.neighbors.split(',').forEach(neighbor => {
                if (neighbor && neighbor !== node.id && neighbor !== "NEIGHBORS:") {
                    if (!isolatedSet.has(neighbor)) {
                        edges.push({ from: node.id, to: neighbor });
                    }
                }
            });
        }
    });

    return (
        <div id="dashboard-root" className="app">
            
            <CommandHeader connectionState={connectionState} />

            <div className="soc-grid">
                <div className="kpi-card">
                    <div className="kpi-header">AGENTS DEPLOYED</div>
                    <div className="kpi-value val-blue">{agentCount}</div>
                </div>
                <div className="kpi-card">
                    <div className="kpi-header">ACTIVE THREATS</div>
                    <div className={compCount > 0 ? "kpi-value val-red" : "kpi-value val-green"}>{compCount}</div>
                </div>
                <div className="kpi-card">
                    <div className="kpi-header">NETWORK CPU LOAD</div>
                    <div className={avgCpu > 0.5 ? "kpi-value val-red" : "kpi-value val-purple"}>{(avgCpu * 100).toFixed(1)}%</div>
                </div>
                <div className="kpi-card">
                    <div className="kpi-header">ALLOCATED RAM</div>
                    <div className="kpi-value val-green">{avgRam} MB</div>
                </div>

                <div className="grid-col-1">
                    <div className="panel">
                        <div className="panel-title">NETWORK RADAR</div>
                        <div className="panel-content" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                            <Radar isThreat={compCount > 0} />
                        </div>
                    </div>
                    <div className="panel">
                        <div className="panel-title">THREAT DISTRIBUTION</div>
                        <div className="panel-content">
                            <Doughnut data={{ labels: ['STABLE', 'COMPROMISED'], datasets: [{ data: [stableCount, compCount], backgroundColor: ['#10B981', '#EF4444'], borderWidth: 0 }] }} options={{ cutout: '75%', plugins: { legend: { position: 'bottom', labels: { color: '#94A3B8' } } } }} />
                        </div>
                    </div>
                </div>

                <div className="grid-col-2">
                    <div className="panel" style={{ flexGrow: 1, marginBottom: '15px' }}>
                        <div className="panel-title">TACTICAL AGENT GRID</div>
                        <div className="panel-content" style={{ padding: 0 }}>
                            <AgentsTable agents={activeNodes} />
                        </div>
                    </div>
                    <div style={{ display: 'flex', gap: '15px', height: '200px' }}>
                        <div className="panel" style={{ flex: 1 }}><div className="panel-title">CPU LOAD</div><div className="panel-content"><Line data={{ labels: timeLabels, datasets: [{ label: 'CPU%', data: cpuData, borderColor: '#8B5CF6', borderWidth: 2, tension: 0.4 }] }} options={chartOptions} /></div></div>
                        <div className="panel" style={{ flex: 1 }}><div className="panel-title">RAM USAGE</div><div className="panel-content"><Line data={{ labels: timeLabels, datasets: [{ label: 'RAM', data: ramData, borderColor: '#3B82F6', borderWidth: 2, tension: 0.4 }] }} options={chartOptions} /></div></div>
                    </div>
                </div>

                <div className="grid-col-3">
                    <div className="panel"><div className="panel-title">P2P TOPOLOGY</div><div className="panel-content" style={{ padding: 0 }}><ForceGraph nodes={activeNodes.map(a => ({ id: a.id, label: a.id, hostname: a.hostname }))} edges={edges} /></div></div>
                    <div className="panel"><div className="panel-title">SECURITY EVENT LOGS</div><div className="panel-content" style={{ padding: '10px' }}><div className="terminal">
                        {logs.length === 0 ? <span style={{color: '#565f89'}}>Awaiting events...</span> : logs.map((log, i) => (
                            <div key={i} className={`log-entry ${log.includes('CRITICAL') || log.includes('INTRUSION') ? 'log-alert' : ''}`}>{log}</div>
                        ))}
                    </div></div></div>
                </div>
            </div>
        </div>
    );
}
export default App;
