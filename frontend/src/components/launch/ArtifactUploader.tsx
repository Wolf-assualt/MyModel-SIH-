import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  CheckCircle2,
  Database,
  Cpu,
  Binary,
  ShieldCheck,
  FolderOpen,
  Zap,
  RotateCcw,
  Check,
} from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import type { ArtifactType } from '../../types/investigation';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

export const ArtifactUploader: React.FC = () => {
  const {
    artifacts,
    updateArtifactWithFile,
    verifyArtifact,
    clearArtifacts,
  } = useInvestigation();

  const [dragOverId, setDragOverId] = useState<string | null>(null);
  const fileInputRefs = useRef<Record<string, HTMLInputElement | null>>({});

  const getArtifactIcon = (type: ArtifactType) => {
    switch (type) {
      case 'dataset':
        return <Database size={22} style={{ color: 'var(--accent-text)' }} />;
      case 'model':
        return <Cpu size={22} style={{ color: 'var(--success-text)' }} />;
      case 'inference':
        return <Binary size={22} style={{ color: 'var(--warning-text)' }} />;
      case 'manifest':
        return <ShieldCheck size={22} style={{ color: 'var(--info-text)' }} />;
    }
  };

  const getAcceptedExtensions = (type: ArtifactType) => {
    switch (type) {
      case 'dataset':
        return '.jpg,.jpeg,.png,.webp,.bmp,.zip,.tar,.tar.gz,.h5,.npy,.csv';
      case 'model':
        return '.onnx,.pt,.pth,.bin,.pb';
      case 'inference':
        return '.json,.jsonl,.csv';
      case 'manifest':
        return '.sig,.sha256,.txt,.pem';
    }
  };

  const handleFileSelect = async (artifactId: string, e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      await updateArtifactWithFile(artifactId, file);
    }
  };

  const handleDrop = async (artifactId: string, e: React.DragEvent) => {
    e.preventDefault();
    setDragOverId(null);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      await updateArtifactWithFile(artifactId, file);
    }
  };

  const allVerified = artifacts.every(a => a.status === 'verified');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Quick Action Top Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem',
          backgroundColor: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: '0.5rem',
          padding: '0.75rem 1.25rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }} className="font-mono">
            INGESTION STATUS:
          </span>
          {allVerified ? (
            <Badge variant="success" size="sm" icon={<Check size={12} />}>
              ALL 4 ARTIFACTS VALIDATED
            </Badge>
          ) : (
            <Badge variant="warning" size="sm">
              {artifacts.filter(a => a.status === 'verified').length} OF 4 READY
            </Badge>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Button
            variant="ghost"
            size="sm"
            onClick={clearArtifacts}
            icon={<RotateCcw size={14} />}
          >
            Reset
          </Button>
        </div>
      </div>

      {/* 4 Cards Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '1.25rem',
        }}
      >
        {artifacts.map(art => {
          const isVerified = art.status === 'verified';
          const isDragOver = dragOverId === art.id;

          return (
            <div
              key={art.id}
              style={{
                backgroundColor: 'var(--surface)',
                borderWidth: '1px',
                borderStyle: 'solid',
                borderColor: isDragOver
                  ? 'var(--accent)'
                  : isVerified
                  ? 'var(--accent)'
                  : 'var(--border)',
                borderRadius: '0.625rem',
                padding: '1.25rem',
                boxShadow: isDragOver
                  ? 'var(--accent-glow)'
                  : isVerified
                  ? 'var(--accent-glow)'
                  : 'var(--card-shadow)',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                transition: 'all 0.2s ease',
              }}
            >
              {/* Hidden File Input */}
              <input
                ref={el => {
                  fileInputRefs.current[art.id] = el;
                }}
                type="file"
                accept={getAcceptedExtensions(art.type)}
                style={{ display: 'none' }}
                onChange={e => handleFileSelect(art.id, e)}
              />

              {/* Top header */}
              <div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '1rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <div
                      style={{
                        width: '38px',
                        height: '38px',
                        borderRadius: '0.375rem',
                        backgroundColor: 'var(--surface-elevated)',
                        border: '1px solid var(--border)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      {getArtifactIcon(art.type)}
                    </div>
                    <div>
                      <h3
                        style={{
                          fontSize: '0.875rem',
                          fontWeight: 700,
                          color: 'var(--text-primary)',
                          textTransform: 'uppercase',
                          margin: 0,
                        }}
                        className="font-display"
                      >
                        {art.title}
                      </h3>
                      <span
                        style={{
                          fontSize: '0.6875rem',
                          color: 'var(--text-muted)',
                        }}
                        className="font-mono"
                      >
                        {art.type.toUpperCase()} ARTIFACT
                      </span>
                    </div>
                  </div>

                  {isVerified ? (
                    <Badge variant="success" size="sm" icon={<CheckCircle2 size={12} />}>
                      READY
                    </Badge>
                  ) : (
                    <Badge variant="default" size="sm">
                      AWAITING
                    </Badge>
                  )}
                </div>

                {/* Artifact Details */}
                <div
                  style={{
                    backgroundColor: 'var(--surface-elevated)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '0.375rem',
                    padding: '0.75rem 1rem',
                    marginBottom: '1rem',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      marginBottom: '0.375rem',
                    }}
                  >
                    <span
                      style={{
                        fontSize: '0.8125rem',
                        fontWeight: art.filename ? 600 : 400,
                        color: art.filename ? 'var(--text-primary)' : 'var(--text-muted)',
                        fontStyle: art.filename ? 'normal' : 'italic',
                      }}
                      className="font-mono"
                    >
                      {art.filename || 'Awaiting file ingestion...'}
                    </span>
                    <span
                      style={{
                        fontSize: '0.75rem',
                        color: 'var(--text-tertiary)',
                        fontWeight: 500,
                      }}
                      className="font-mono"
                    >
                      {art.size !== '0 B' ? art.size : '—'}
                    </span>
                  </div>

                  {/* SHA-256 display */}
                  <div
                    style={{
                      fontSize: '0.6875rem',
                      color: 'var(--text-muted)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.375rem',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    className="font-mono"
                  >
                    <span style={{ color: 'var(--text-tertiary)', fontWeight: 600 }}>SHA-256:</span>
                    {art.hash ? (
                      <span style={{ color: 'var(--accent-text)' }}>
                        {art.hash.substring(0, 16)}...{art.hash.substring(art.hash.length - 8)}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>
                        Pending ingestion hash
                      </span>
                    )}
                  </div>

                  {Boolean(art.metadata?.samplesCount) && (
                    <div
                      style={{
                        marginTop: '0.375rem',
                        fontSize: '0.6875rem',
                        color: 'var(--text-secondary)',
                      }}
                      className="font-mono"
                    >
                      Payload: {art.metadata?.samplesCount?.toLocaleString()} visual frame(s)
                    </div>
                  )}
                  {Boolean(art.metadata?.layersCount) && (
                    <div
                      style={{
                        marginTop: '0.375rem',
                        fontSize: '0.6875rem',
                        color: 'var(--text-secondary)',
                      }}
                      className="font-mono"
                    >
                      Architecture: {art.metadata?.layersCount} Neural Layers ({art.metadata?.format})
                    </div>
                  )}
                  {Boolean(art.metadata?.recordsCount) && (
                    <div
                      style={{
                        marginTop: '0.375rem',
                        fontSize: '0.6875rem',
                        color: 'var(--text-secondary)',
                      }}
                      className="font-mono"
                    >
                      Telemetry: {art.metadata?.recordsCount?.toLocaleString()} ground-truth records
                    </div>
                  )}
                  {!art.metadata?.samplesCount && !art.metadata?.layersCount && !art.metadata?.recordsCount && art.metadata?.format && (
                    <div
                      style={{
                        marginTop: '0.375rem',
                        fontSize: '0.6875rem',
                        color: 'var(--text-muted)',
                      }}
                      className="font-mono"
                    >
                      Accepted: {art.metadata.format}
                    </div>
                  )}
                </div>
              </div>

              {/* Interactive Drop / Verified Zone */}
              <div
                onClick={() => fileInputRefs.current[art.id]?.click()}
                onDragOver={e => {
                  e.preventDefault();
                  setDragOverId(art.id);
                }}
                onDragLeave={() => setDragOverId(null)}
                onDrop={e => handleDrop(art.id, e)}
                style={{
                  border: `1px dashed ${
                    isDragOver
                      ? 'var(--accent)'
                      : isVerified
                      ? 'var(--success-border)'
                      : 'var(--border-strong)'
                  }`,
                  borderRadius: '0.375rem',
                  padding: '0.75rem',
                  textAlign: 'center',
                  backgroundColor: isDragOver
                    ? 'var(--accent-surface)'
                    : isVerified
                    ? 'var(--success-surface)'
                    : 'var(--surface-elevated)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '0.5rem',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  userSelect: 'none',
                }}
                title="Click to browse files or drag & drop"
              >
                {isVerified ? (
                  <>
                    <CheckCircle2 size={16} style={{ color: 'var(--success-text)' }} />
                    <span
                      style={{
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        color: 'var(--success-text)',
                      }}
                      className="font-mono"
                    >
                      INTEGRITY HASH VALIDATED (Click to replace)
                    </span>
                  </>
                ) : (
                  <>
                    <UploadCloud size={16} style={{ color: 'var(--accent-text)' }} />
                    <span
                      style={{
                        fontSize: '0.75rem',
                        color: 'var(--accent-text)',
                        fontWeight: 600,
                      }}
                      className="font-mono"
                    >
                      CLICK TO UPLOAD OR DRAG & DROP
                    </span>
                  </>
                )}
              </div>

              {/* Direct Card Action Buttons */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  marginTop: '0.75rem',
                }}
              >
                <Button
                  variant="outline"
                  size="sm"
                  style={{ flex: 1 }}
                  onClick={() => fileInputRefs.current[art.id]?.click()}
                  icon={<FolderOpen size={13} />}
                >
                  Choose File
                </Button>

                {!isVerified ? (
                  <Button
                    variant="secondary"
                    size="sm"
                    style={{ flex: 1 }}
                    onClick={() => verifyArtifact(art.id)}
                    icon={<Zap size={13} style={{ color: 'var(--accent-text)' }} />}
                  >
                    Quick Verify
                  </Button>
                ) : (
                  <Button
                    variant="ghost"
                    size="sm"
                    style={{ flex: 1 }}
                    onClick={() => verifyArtifact(art.id)}
                    icon={<CheckCircle2 size={13} style={{ color: 'var(--success-text)' }} />}
                  >
                    Verified ✓
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
