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
        return <Badge variant="critical" size="sm">CRITICAL</Badge>;
      case 'HIGH':
        return <Badge variant="danger" size="sm">HIGH</Badge>;
      case 'WARNING':
      case 'MEDIUM':
        return <Badge variant="warning" size="sm">WARNING</Badge>;
      case 'LOW':
      case 'INFO':
      default:
        return <Badge variant="info" size="sm">INFO</Badge>;
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
      {/* Header with Title & Search */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '1rem',
        }}
      >
        <div>
          <h3
            style={{
              fontSize: '1.125rem',
              fontWeight: 700,
              color: 'var(--text-primary)',
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              margin: 0,
            }}
            className="font-display"
          >
            Forensic Findings & Evidence Log
          </h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0 }}>
            Showing {filteredFindings.length} of {findings.length} total integrity findings
          </p>
        </div>

        {/* Search & Severity Filter Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          {/* Search Box */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              backgroundColor: 'var(--surface-elevated)',
              border: '1px solid var(--border)',
              borderRadius: '0.375rem',
              padding: '0.375rem 0.75rem',
            }}
          >
            <Search size={14} style={{ color: 'var(--text-muted)' }} />
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
              className="font-mono"
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
            className="font-mono"
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
          gap: '0.375rem',
          overflowX: 'auto',
          paddingBottom: '0.25rem',
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
                fontSize: '0.75rem',
                fontWeight: isSelected ? 600 : 500,
                border: '1px solid',
                borderColor: isSelected ? 'var(--accent)' : 'var(--border)',
                backgroundColor: isSelected ? 'var(--accent-surface)' : 'var(--surface-elevated)',
                color: isSelected ? 'var(--accent-text)' : 'var(--text-secondary)',
                borderRadius: '0.375rem',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'all 0.15s ease',
              }}
              className="font-mono"
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
            padding: '3rem 2rem',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.75rem',
            backgroundColor: 'var(--surface-elevated)',
            borderRadius: '0.5rem',
            border: '1px solid var(--success-border)',
          }}
        >
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '50%',
              backgroundColor: 'var(--success-surface)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--success-text)',
            }}
          >
            <ShieldCheck size={28} />
          </div>
          <h4 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }} className="font-display">
            Zero Forensic Vulnerabilities Detected
          </h4>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', maxWidth: '540px', margin: 0, lineHeight: 1.5 }}>
            All cryptographic checksums, latent space embeddings, and neural parameter weights conform to Golden Baseline specifications with zero anomalies.
          </p>
          <Badge variant="success" size="sm">
            ✓ 100% CLEAN ZERO-TRUST AUDIT
          </Badge>
        </div>
      ) : (
        <div
          style={{
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
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
                  className="font-mono"
                >
                  <th style={{ padding: '0.75rem 1rem', width: '110px' }}>SEVERITY</th>
                  <th style={{ padding: '0.75rem 1rem', width: '130px' }}>ID</th>
                  <th style={{ padding: '0.75rem 1rem' }}>FINDING</th>
                  <th style={{ padding: '0.75rem 1rem', width: '130px' }}>CATEGORY</th>
                  <th style={{ padding: '0.75rem 1rem' }}>AFFECTED ARTIFACT</th>
                  <th style={{ padding: '0.75rem 1rem', width: '100px' }}>CONFIDENCE</th>
                  <th style={{ padding: '0.75rem 1rem', width: '100px' }}>STATUS</th>
                  <th style={{ padding: '0.75rem 1rem', width: '90px', textAlign: 'center' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
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
                    <td style={{ padding: '0.75rem 1rem' }}>{getSeverityBadge(f.severity)}</td>
                    <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: 'var(--accent-text)' }} className="font-mono">
                      {f.id}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{f.title}</div>
                      <div
                        style={{
                          fontSize: '0.75rem',
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
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span
                        style={{
                          fontSize: '0.6875rem',
                          padding: '2px 6px',
                          borderRadius: '3px',
                          backgroundColor: 'var(--surface-active)',
                          color: 'var(--text-secondary)',
                        }}
                        className="font-mono"
                      >
                        {f.category}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }} className="font-mono">
                      {f.affectedArtifact}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: 'var(--text-primary)' }} className="font-mono">
                      {f.confidence}%
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span
                        style={{
                          fontSize: '0.6875rem',
                          fontWeight: 600,
                          color: f.status === 'Confirmed' ? 'var(--critical-text)' : 'var(--warning-text)',
                        }}
                        className="font-mono"
                      >
                        ● {f.status}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem', textAlign: 'center' }}>
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
                          gap: '0.25rem',
                          fontSize: '0.6875rem',
                        }}
                        className="font-mono"
                        title="Inspect Finding Evidence"
                      >
                        <Eye size={12} />
                        VIEW
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
