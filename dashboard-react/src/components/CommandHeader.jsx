import React, { useState } from 'react';

export const CommandHeader = () => {
    const [isInjecting, setIsInjecting] = useState(false);
    const [errorState, setErrorState] = useState(null);

    const handleInjectThreat = async () => {
        if (isInjecting) return;

        setIsInjecting(true);
        setErrorState(null);

        try {
            const response = await fetch('http://localhost:4000/api/inject-threat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!response.ok) {
                throw new Error(`Command rejected by Bridge. Status: ${response.status}`);
            }

            console.log("[C2] Threat injection signal transmitted successfully.");
            
        } catch (error) {
            console.error("[C2] Command Bridge communication failure:", error);
            setErrorState("BRIDGE CONNECTION REFUSED");
        } finally {
            // Enforce 2000ms cooldown to protect the C++ UDP buffers from flooding
            setTimeout(() => {
                setIsInjecting(false);
            }, 2000);
        }
    };

    return (
        <header className="command-header" style={styles.header}>
            <div className="header-title">
                <h2 style={styles.title}>NEURO-MESH COMMAND CENTER</h2>
            </div>
            
            <div className="header-actions" style={styles.actions}>
                <span className="c2-status" style={styles.status}>C2 CENTRAL (CONNECTED)</span>
                
                {errorState && (
                    <span className="error-toast" style={styles.errorText}>
                        [{errorState}]
                    </span>
                )}

                <button 
                    className="inject-threat-btn"
                    onClick={handleInjectThreat}
                    disabled={isInjecting}
                    style={{
                        ...styles.button,
                        ...(isInjecting ? styles.buttonDisabled : styles.buttonActive)
                    }}
                >
                    {isInjecting ? "EXECUTING..." : "INJECT THREAT"}
                </button>
            </div>
        </header>
    );
};

const styles = {
    header: { 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        padding: '15px 30px', 
        backgroundColor: '#0f172a', 
        borderBottom: '1px solid #1e293b' 
    },
    title: { color: '#ffffff', margin: 0, fontSize: '18px', letterSpacing: '1px' },
    actions: { display: 'flex', alignItems: 'center', gap: '20px' },
    status: { color: '#10b981', fontSize: '12px', fontWeight: 'bold' },
    errorText: { color: '#ef4444', fontSize: '12px', fontWeight: 'bold' },
    button: { 
        padding: '8px 16px', 
        borderRadius: '4px', 
        border: 'none', 
        fontWeight: 'bold', 
        cursor: 'pointer', 
        transition: 'all 0.2s' 
    },
    buttonActive: { backgroundColor: '#ef4444', color: '#ffffff' },
    buttonDisabled: { backgroundColor: '#475569', color: '#94a3b8', cursor: 'not-allowed' }
};
