import { useState, useEffect } from 'react';
import { io } from 'socket.io-client';

export const useNeuroTelemetry = () => {
    const [events, setEvents] = useState([]);
    const [activeThreats, setActiveThreats] = useState(0);
    const [isolatedNodes, setIsolatedNodes] = useState(new Set());

    useEffect(() => {
        // Connect to your Node.js Sidecar
        const socket = io('http://localhost:4000');

        socket.on('mesh_event', (data) => {
            // 1. Update the "SECURITY EVENT LOGS" terminal
            setEvents(prev => [...prev, `[${data.node}] ${data.event} -> ${data.target}`].slice(-50));

            // 2. Update the "MENACES ACTIVES" counter
            if (data.event === "THREAT_DETECTED") {
                setActiveThreats(prev => prev + 1);
            }

            // 3. Update the "TACTICAL AGENT GRID" status
            if (data.event.includes("ISOLATED") || data.event.includes("BLOCKLISTED")) {
                setIsolatedNodes(prev => {
                    const next = new Set(prev);
                    next.add(data.target);
                    return next;
                });
            }
        });

        return () => socket.disconnect();
    }, []);

    return { events, activeThreats, isolatedNodes };
};
