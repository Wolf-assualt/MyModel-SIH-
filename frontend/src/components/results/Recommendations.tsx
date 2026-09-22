import React, { useState } from 'react';
import { Check } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import type { Recommendation } from '../../types/investigation';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

export const Recommendations: React.FC = () => {
  const { recommendations, exportEvidencePackage } = useInvestigation();
  const [executedActions, setExecutedActions] = useState<Record<string, boolean>>({});

  const handleActionClick = (rec: Recommendation) => {
    setExecutedActions(prev => ({ ...prev, [rec.id]: true }));
    if (rec.actionType === 'export') {
      exportEvidencePackage();
    }
  };

  const getPriorityBadge = (priority: Recommendation['priority']) => {
    switch (priority) {
      case 'IMMEDIATE':
        return <Badge variant="critical" size="sm">IMMEDIATE</Badge>;
      case 'HIGH':
        return <Badge variant="warning" size="sm">HIGH</Badge>;
      case 'MEDIUM':
      default:
        return <Badge variant="accent" size="sm">MEDIUM</Badge>;
    }
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '0.625rem',
        padding: '1.5rem',
        boxShadow: 'var(--card-shadow)',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '0.75rem',
        }}
      >
        <div>
          <h3
            style={{
              fontSize: '16px',
              fontWeight: 600,
              color: 'var(--text-primary)',
              letterSpacing: '-0.01em',
              margin: 0,
            }}
          >
            Actionable Forensic Mitigation Playbook
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0 0' }}>
            Mandatory defense countermeasures required before granting mission operational authorization
          </p>
        </div>

        <Badge variant={recommendations.length > 0 ? 'accent' : 'success'} size="sm">
          {recommendations.length} CONTROLS
        </Badge>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {recommendations.length === 0 ? (
          <div
            style={{
              padding: '2.5rem 1.5rem',
              textAlign: 'center',
              backgroundColor: 'var(--surface-elevated)',
              borderRadius: '0.5rem',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--success-text)', marginBottom: '0.25rem' }}>
              ✓ No Remediation Actions Required
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Zero-trust verification assertions satisfied. Operational deployment countermeasures are not required for this asset.
            </div>
          </div>
        ) : (
          recommendations.map(rec => {
          const isExecuted = Boolean(executedActions[rec.id]);

          return (
            <div
              key={rec.id}
              style={{
                backgroundColor: 'var(--surface-elevated)',
                borderWidth: '1px',
                borderStyle: 'solid',
                borderColor: isExecuted ? 'var(--success-border)' : 'var(--border)',
                borderRadius: '8px',
                padding: '16px 20px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '1rem',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ maxWidth: '850px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', marginBottom: '0.25rem' }}>
                  {getPriorityBadge(rec.priority)}
                  <h4
                    style={{
                      fontSize: '0.9375rem',
                      fontWeight: 500,
                      color: 'var(--text-primary)',
                      margin: 0,
                    }}
                  >
                    {rec.title}
                  </h4>
                </div>
                <p
                  style={{
                    fontSize: '0.8125rem',
                    color: 'var(--text-secondary)',
                    margin: 0,
                    lineHeight: 1.5,
                  }}
                >
                  {rec.description}
                </p>
              </div>

              <div>
                <Button
                  variant={isExecuted ? 'outline' : rec.priority === 'IMMEDIATE' ? 'danger' : 'primary'}
                  size="sm"
                  onClick={() => handleActionClick(rec)}
                  disabled={isExecuted}
                  icon={isExecuted ? <Check size={14} style={{ color: 'var(--success-text)' }} /> : undefined}
                >
                  {isExecuted ? 'Executed' : rec.actionLabel}
                </Button>
              </div>
            </div>
          );
        }))}
      </div>
    </div>
  );
};
