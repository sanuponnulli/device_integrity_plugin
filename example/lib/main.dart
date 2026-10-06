import 'package:flutter/material.dart';
import 'package:device_integrity/device_integrity.dart';

void main() {
  runApp(const DeviceIntegrityExampleApp());
}

class DeviceIntegrityExampleApp extends StatelessWidget {
  const DeviceIntegrityExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Device Integrity Demo',
      theme: ThemeData(
        colorSchemeSeed: const Color(0xFF1A73E8),
        useMaterial3: true,
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        colorSchemeSeed: const Color(0xFF1A73E8),
        useMaterial3: true,
        brightness: Brightness.dark,
      ),
      home: const IntegrityDashboard(),
    );
  }
}

class IntegrityDashboard extends StatefulWidget {
  const IntegrityDashboard({super.key});

  @override
  State<IntegrityDashboard> createState() => _IntegrityDashboardState();
}

class _IntegrityDashboardState extends State<IntegrityDashboard> {
  final _plugin = DeviceIntegrityPlugin.instance;

  IntegrityReport? _report;
  List<IntegrityCapability>? _capabilities;
  bool _loading = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadCapabilities();
  }

  Future<void> _loadCapabilities() async {
    try {
      final caps = await _plugin.getCapabilities();
      if (mounted) setState(() => _capabilities = caps);
    } catch (e) {
      if (mounted) setState(() => _error = 'Capabilities: $e');
    }
  }

  Future<void> _runLocalChecks() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final report = await _plugin.checkLocalSignals();
      if (mounted) {
        setState(() {
          _report = report;
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = '$e';
          _loading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Device Integrity'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _loading ? null : _runLocalChecks,
            tooltip: 'Run local checks',
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ── Capabilities ──────────────────────────────────────────
          if (_capabilities != null) ...[
            Text('Capabilities', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 4,
              children: _capabilities!.map((c) {
                return Chip(
                  avatar: Icon(
                    c.available ? Icons.check_circle : Icons.cancel,
                    size: 18,
                    color: c.available ? Colors.green : Colors.orange,
                  ),
                  label: Text(c.id, style: const TextStyle(fontSize: 12)),
                );
              }).toList(),
            ),
            const Divider(height: 32),
          ],

          // ── Run button ────────────────────────────────────────────
          if (_report == null && !_loading)
            FilledButton.icon(
              onPressed: _runLocalChecks,
              icon: const Icon(Icons.security),
              label: const Text('Run Local Integrity Checks'),
            ),

          if (_loading) const Center(child: CircularProgressIndicator()),

          if (_error != null)
            Card(
              color: theme.colorScheme.errorContainer,
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Text(
                  _error!,
                  style: TextStyle(color: theme.colorScheme.onErrorContainer),
                ),
              ),
            ),

          // ── Report metadata ───────────────────────────────────────
          if (_report != null) ...[
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Report', style: theme.textTheme.titleMedium),
                    const SizedBox(height: 8),
                    _metaRow('Platform', _report!.platform),
                    _metaRow('OS Version', _report!.osVersion),
                    _metaRow('Plugin Version', _report!.packageVersion),
                    _metaRow('Check Time',
                        _report!.checkTime.toLocal().toString()),
                    _metaRow('Findings', '${_report!.findings.length}'),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // ── Individual findings ─────────────────────────────────
            Text('Findings', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            ..._report!.findings.map((f) => _FindingCard(finding: f)),
          ],
        ],
      ),
    );
  }

  Widget _metaRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          SizedBox(
            width: 120,
            child: Text(label,
                style: const TextStyle(fontWeight: FontWeight.w500)),
          ),
          Expanded(child: Text(value)),
        ],
      ),
    );
  }
}

class _FindingCard extends StatelessWidget {
  final IntegrityFinding finding;

  const _FindingCard({required this.finding});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    final (icon, color) = switch (finding.status) {
      FindingStatus.detected => (Icons.warning_amber, Colors.red),
      FindingStatus.notDetected => (Icons.check_circle_outline, Colors.green),
      FindingStatus.unavailable => (Icons.help_outline, Colors.orange),
      FindingStatus.error => (Icons.error_outline, Colors.red.shade300),
    };

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: Icon(icon, color: color),
        title: Text(finding.signalId),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '${finding.status.name} · ${finding.source.name}',
              style: TextStyle(
                fontSize: 12,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            Text(
              'Reason: ${finding.reasonCode}',
              style: const TextStyle(fontSize: 12),
            ),
            if (finding.detail != null)
              Text(
                finding.detail!,
                style: TextStyle(
                  fontSize: 11,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
          ],
        ),
        isThreeLine: true,
      ),
    );
  }
}
