import React, { useState, useRef } from 'react';
import { motion } from 'framer-motion';
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
import { ProvenanceChain } from './ProvenanceChain';

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
        return <Database size={18} strokeWidth={1.5} style={{ color: 'var(--text-secondary)' }} />;
      case 'model':
        return <Cpu size={18} strokeWidth={1.5} style={{ color: 'var(--text-secondary)' }} />;
      case 'inference':
        return <Binary size={18} strokeWidth={1.5} style={{ color: 'var(--text-secondary)' }} />;
      case 'manifest':
        return <ShieldCheck size={18} strokeWidth={1.5} style={{ color: 'var(--text-secondary)' }} />;
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Quick Action Top Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
          backgroundColor: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: '12px',
          padding: '12px 20px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
            Ingestion status:
          </span>
          {allVerified ? (
            <Badge variant="success" size="sm" icon={<Check size={12} strokeWidth={1.5} />}>
              All 4 artifacts validated
            </Badge>
          ) : (
            <Badge variant="warning" size="sm">
              {artifacts.filter(a => a.status === 'verified').length} of 4 ready
            </Badge>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Button
            variant="ghost"
            size="sm"
            onClick={clearArtifacts}
            icon={<RotateCcw size={14} strokeWidth={1.5} />}
          >
            Reset
          </Button>
        </div>
      </div>

      {/* 4 Cards Grid */}
      <motion.div
        initial="hidden"
        animate="visible"
        variants={{ visible: { transition: { staggerChildren: 0.05 } } }}
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '24px',
        }}
      >
        {artifacts.map(art => {
          const isVerified = art.status === 'verified';
          const isUploading = art.status === 'uploading';
          const isDragOver = dragOverId === art.id;

          return (
            <motion.div
              key={art.id}
              id={`artifact-card-${art.id}`}
              variants={{
                hidden: { opacity: 0, y: 10 },
                visible: { opacity: 1, y: 0, transition: { duration: 0.25, ease: 'easeOut' } },
              }}
              style={{
                backgroundColor: 'var(--surface)',
                borderWidth: '1px',
                borderStyle: 'solid',
                borderColor: isDragOver ? 'var(--accent)' : 'var(--border)',
                borderRadius: '12px',
                padding: '20px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                transition: 'border-color 0.15s ease',
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
                    marginBottom: '16px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div
                      style={{
                        width: '36px',
                        height: '36px',
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
                          fontWeight: 600,
                          color: 'var(--text-primary)',
                          margin: 0,
                        }}
                      >
                        {art.title}
                      </h3>
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {art.type} artifact
                      </span>
                    </div>
                  </div>

                  {isUploading ? (
                    <Badge variant="accent" size="sm">
                      Ingesting
                    </Badge>
                  ) : isVerified ? (
                    <Badge variant="success" size="sm" icon={<CheckCircle2 size={12} strokeWidth={1.5} />}>
                      Ready
                    </Badge>
                  ) : (
                    <Badge variant="default" size="sm">
                      Awaiting
                    </Badge>
                  )}
                </div>

                {/* Artifact Details */}
                <div
                  style={{
                    backgroundColor: 'var(--surface-elevated)',
                    border: '1px solid var(--border)',
                    borderRadius: '0.375rem',
                    padding: '12px 16px',
                    marginBottom: '16px',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      marginBottom: '6px',
                    }}
                  >
                    <span
                      style={{
                        fontSize: '0.8125rem',
                        fontWeight: art.filename ? 500 : 400,
                        color: art.filename ? 'var(--text-primary)' : 'var(--text-muted)',
                        fontStyle: art.filename ? 'normal' : 'italic',
                      }}
                    >
                      {art.filename || 'Awaiting file ingestion...'}
                    </span>
                    <span
                      className="font-mono"
                      style={{
                        fontSize: '12px',
                        color: 'var(--text-muted)',
                        fontWeight: 500,
                      }}
                    >
                      {art.size !== '0 B' ? art.size : '—'}
                    </span>
                  </div>

                  {/* SHA-256 display */}
                  <div
                    style={{
                      fontSize: '11px',
                      color: 'var(--text-muted)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    className="font-mono"
                  >
                    <span>SHA-256:</span>
                    {isUploading ? (
                      <span className="skeleton" style={{ display: 'inline-block', width: '160px', height: '0.75rem' }} />
                    ) : art.hash ? (
                      <span style={{ color: 'var(--text-secondary)' }}>
                        {art.hash.substring(0, 16)}...{art.hash.substring(art.hash.length - 8)}
                      </span>
                    ) : (
                      <span style={{ fontStyle: 'italic' }}>
                        Pending ingestion hash
                      </span>
                    )}
                  </div>

                  {/* Provenance chain visual once the manifest carries a signature/hash */}
                  {art.type === 'manifest' && isVerified && <ProvenanceChain />}

                  {Boolean(art.metadata?.samplesCount) && (
                    <div
                      style={{
                        marginTop: '6px',
                        fontSize: '12px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      Payload: {art.metadata?.samplesCount?.toLocaleString()} visual frame(s)
                    </div>
                  )}
                  {Boolean(art.metadata?.layersCount) && (
                    <div
                      style={{
                        marginTop: '6px',
                        fontSize: '12px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      Architecture: {art.metadata?.layersCount} neural layers ({art.metadata?.format})
                    </div>
                  )}
                  {Boolean(art.metadata?.recordsCount) && (
                    <div
                      style={{
                        marginTop: '6px',
                        fontSize: '12px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      Telemetry: {art.metadata?.recordsCount?.toLocaleString()} ground-truth records
                    </div>
                  )}
                  {!art.metadata?.samplesCount && !art.metadata?.layersCount && !art.metadata?.recordsCount && art.metadata?.format && (
                    <div
                      style={{
                        marginTop: '6px',
                        fontSize: '12px',
                        color: 'var(--text-muted)',
                      }}
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
                      : 'var(--border-strong)'
                  }`,
                  borderRadius: '0.375rem',
                  padding: '12px',
                  textAlign: 'center',
                  backgroundColor: isDragOver ? 'var(--accent-surface)' : 'var(--surface-elevated)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  cursor: 'pointer',
                  transition: 'border-color 0.15s ease, background-color 0.15s ease',
                  userSelect: 'none',
                }}
                title="Click to browse files or drag & drop"
              >
                {isVerified ? (
                  <>
                    <CheckCircle2 size={16} strokeWidth={1.5} style={{ color: 'var(--success-text)' }} />
                    <span
                      style={{
                        fontSize: '12px',
                        fontWeight: 500,
                        color: 'var(--text-secondary)',
                      }}
                    >
                      Integrity hash validated (click to replace)
                    </span>
                  </>
                ) : (
                  <>
                    <UploadCloud size={16} strokeWidth={1.5} style={{ color: 'var(--text-secondary)' }} />
                    <span
                      style={{
                        fontSize: '12px',
                        color: 'var(--text-secondary)',
                        fontWeight: 500,
                      }}
                    >
                      Click to upload or drag & drop
                    </span>
                  </>
                )}
              </div>

              {/* Direct Card Action Buttons */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  marginTop: '12px',
                }}
              >
                <Button
                  variant="outline"
                  size="sm"
                  style={{ flex: 1 }}
                  onClick={() => fileInputRefs.current[art.id]?.click()}
                  icon={<FolderOpen size={13} strokeWidth={1.5} />}
                  className="choose-file-btn"
                >
                  Choose File
                </Button>

                {!isVerified ? (
                  <Button
                    variant="primary"
                    size="sm"
                    style={{ flex: 1 }}
                    onClick={() => verifyArtifact(art.id)}
                    icon={<Zap size={13} strokeWidth={1.5} />}
                  >
                    Quick Verify
                  </Button>
                ) : (
                  <Button
                    variant="ghost"
                    size="sm"
                    style={{ flex: 1 }}
                    onClick={() => verifyArtifact(art.id)}
                    icon={<CheckCircle2 size={13} strokeWidth={1.5} style={{ color: 'var(--success-text)' }} />}
                  >
                    Verified ✓
                  </Button>
                )}
              </div>
            </motion.div>
          );
        })}
      </motion.div>
    </div>
  );
};
