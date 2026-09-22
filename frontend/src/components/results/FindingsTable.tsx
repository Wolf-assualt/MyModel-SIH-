import React from 'react';
import { Search, Eye, ShieldCheck } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import type { FindingCategory, Severity } from '../../types/investigation';
import { Badge } from '../ui/Badge';

export const FindingsTable: React.FC = () => {
  const {
    findings,
    selectedCategory,
    setSelectedCategory,
    selectedSeverity,
    setSelectedSeverity,
    searchQuery,
    setSearchQuery,
    setSelectedFinding,
  } = useInvestigation();

  const categories: FindingCategory[] = [
    'ALL',
    'DATA POISONING',
    'BACKDOOR',
    'MODEL INTEGRITY',
    'INFERENCE',
    'OOD',
    'DUPLICATES',
    'MISLABELING',
    'METADATA',
    'PIPELINE',
  ];

  // Filtering
  const filteredFindings = findings.filter(f => {
    // Category filter
    if (selectedCategory !== 'ALL' && f.category !== selectedCategory) return false;

    // Severity filter
    if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchesTitle = f.title.toLowerCase().includes(q);
      const matchesId = f.id.toLowerCase().includes(q);
      const matchesArtifact = f.affectedArtifact.toLowerCase().includes(q);
      const matchesEvidence = f.evidenceSummary.toLowerCase().includes(q);
      if (!matchesTitle && !matchesId && !matchesArtifact && !matchesEvidence) return false;
    }

    return true;
  });

  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return <Badge variant="critical" size="sm">Critical</Badge>;
      case 'HIGH':
        return <Badge variant="danger" size="sm">High</Badge>;
      case 'WARNING':
      case 'MEDIUM':
        return <Badge variant="warning" size="sm">Warning</Badge>;
      case 'LOW':
      case 'INFO':
      default:
        return <Badge variant="info" size="sm">Info</Badge>;
    }
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '12px',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
      }}
    >
      {/* Header with Title & Search */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '16px',
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
            Forensic Findings & Evidence Log
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0 0' }}>
            Showing {filteredFindings.length} of {findings.length} total integrity findings
          </p>
        </div>

        {/* Search & Severity Filter Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          {/* Search Box */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              backgroundColor: 'var(--surface-elevated)',
              border: '1px solid var(--border)',
              borderRadius: '0.375rem',
              padding: '0.375rem 0.75rem',
            }}
          >
            <Search size={14} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search findings, samples, hashes..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              style={{
                backgroundColor: 'transparent',
                border: 'none',
                outline: 'none',
                color: 'var(--text-primary)',
                fontSize: '0.8125rem',
                width: '210px',
              }}
            />
          </div>

          {/* Severity Dropdown */}
          <select
            value={selectedSeverity}
            onChange={e => setSelectedSeverity(e.target.value)}
            style={{
              backgroundColor: 'var(--surface-elevated)',
              border: '1px solid var(--border)',
              borderRadius: '0.375rem',
              padding: '0.375rem 0.75rem',
              color: 'var(--text-primary)',
              fontSize: '0.8125rem',
              outline: 'none',
              cursor: 'pointer',
            }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="WARNING">Warning</option>
          </select>
        </div>
      </div>

      {/* Category Tabs */}
      <div
        style={{
          display: 'flex',
          gap: '6px',
          overflowX: 'auto',
          paddingBottom: '4px',
        }}
      >
        {categories.map(cat => {
          const isSelected = selectedCategory === cat;
          const count =
            cat === 'ALL'
              ? findings.length
              : findings.filter(f => f.category === cat).length;

          return (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              style={{
                padding: '0.375rem 0.75rem',
                fontSize: '12px',
                fontWeight: isSelected ? 500 : 400,
                border: '1px solid',
                borderColor: isSelected ? 'var(--accent-border)' : 'var(--border)',
                backgroundColor: isSelected ? 'var(--accent-surface)' : 'var(--surface-elevated)',
                color: isSelected ? 'var(--accent-text)' : 'var(--text-secondary)',
                borderRadius: '0.375rem',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'border-color 0.15s ease, color 0.15s ease',
              }}
            >
              {cat} ({count})
            </button>
          );
        })}
      </div>

      {/* Forensic Table or Clean Audit Banner */}
      {findings.length === 0 ? (
        <div
          style={{
            padding: '48px 32px',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '12px',
            backgroundColor: 'var(--surface-elevated)',
            borderRadius: '8px',
            border: '1px solid var(--border)',
          }}
        >
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '50%',
              backgroundColor: 'var(--surface)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--success-text)',
            }}
          >
            <ShieldCheck size={24} strokeWidth={1.5} />
          </div>
          <h4 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
            Zero Forensic Vulnerabilities Detected
          </h4>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', maxWidth: '540px', margin: 0, lineHeight: 1.5 }}>
            All cryptographic checksums, latent space embeddings, and neural parameter weights conform to Golden Baseline specifications with zero anomalies.
          </p>
          <Badge variant="success" size="sm">
            100% clean audit
          </Badge>
        </div>
      ) : (
        <div
          style={{
            border: '1px solid var(--border)',
            borderRadius: '8px',
            overflow: 'hidden',
          }}
        >
          <div style={{ overflowX: 'auto' }}>
            <table
              style={{
                width: '100%',
                borderCollapse: 'collapse',
                textAlign: 'left',
                fontSize: '0.8125rem',
              }}
            >
              <thead>
                <tr
                  style={{
                    backgroundColor: 'var(--surface-elevated)',
                    borderBottom: '1px solid var(--border)',
                    color: 'var(--text-muted)',
                  }}
                >
                  <th style={{ padding: '12px 16px', width: '110px', fontSize: '12px', fontWeight: 500 }}>Severity</th>
                  <th style={{ padding: '12px 16px', width: '130px', fontSize: '12px', fontWeight: 500 }}>ID</th>
                  <th style={{ padding: '12px 16px', fontSize: '12px', fontWeight: 500 }}>Finding</th>
                  <th style={{ padding: '12px 16px', width: '130px', fontSize: '12px', fontWeight: 500 }}>Category</th>
                  <th style={{ padding: '12px 16px', fontSize: '12px', fontWeight: 500 }}>Affected artifact</th>
                  <th style={{ padding: '12px 16px', width: '100px', fontSize: '12px', fontWeight: 500 }}>Confidence</th>
                  <th style={{ padding: '12px 16px', width: '100px', fontSize: '12px', fontWeight: 500 }}>Status</th>
                  <th style={{ padding: '12px 16px', width: '90px', textAlign: 'center', fontSize: '12px', fontWeight: 500 }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No findings matching selected category and filter parameters.
                    </td>
                  </tr>
                ) : (
                filteredFindings.map((f, i) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      backgroundColor: i % 2 === 0 ? 'var(--surface)' : 'var(--surface-elevated)',
                      cursor: 'pointer',
                      transition: 'background-color 0.15s ease',
                    }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--surface-hover)')}
                    onMouseLeave={e =>
                      (e.currentTarget.style.backgroundColor =
                        i % 2 === 0 ? 'var(--surface)' : 'var(--surface-elevated)')
                    }
                  >
                    <td style={{ padding: '12px 16px' }}>{getSeverityBadge(f.severity)}</td>
                    <td style={{ padding: '12px 16px', fontWeight: 500, color: 'var(--text-secondary)' }} className="font-mono">
                      {f.id}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{f.title}</div>
                      <div
                        style={{
                          fontSize: '12px',
                          color: 'var(--text-muted)',
                          maxWidth: '380px',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {f.evidenceSummary}
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span
                        style={{
                          fontSize: '11px',
                          padding: '2px 8px',
                          borderRadius: '999px',
                          backgroundColor: 'var(--surface)',
                          border: '1px solid var(--border)',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        {f.category}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px', color: 'var(--text-secondary)' }} className="font-mono">
                      {f.affectedArtifact}
                    </td>
                    <td style={{ padding: '12px 16px', fontWeight: 500, color: 'var(--text-primary)' }} className="font-mono">
                      {f.confidence}%
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span
                        style={{
                          fontSize: '12px',
                          fontWeight: 500,
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                          color: f.status === 'Confirmed' ? 'var(--critical-text)' : 'var(--warning-text)',
                        }}
                      >
                        <span
                          style={{
                            width: '6px',
                            height: '6px',
                            borderRadius: '50%',
                            backgroundColor: 'currentColor',
                            display: 'inline-block',
                          }}
                          aria-hidden="true"
                        />
                        {f.status}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                      <button
                        onClick={e => {
                          e.stopPropagation();
                          setSelectedFinding(f);
                        }}
                        style={{
                          background: 'transparent',
                          border: '1px solid var(--border)',
                          borderRadius: '0.25rem',
                          padding: '0.25rem 0.5rem',
                          color: 'var(--accent-text)',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          fontSize: '11px',
                        }}
                        title="Inspect Finding Evidence"
                      >
                        <Eye size={12} strokeWidth={1.5} />
                        View
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      )}
    </div>
  );
};
