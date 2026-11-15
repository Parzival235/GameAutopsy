const reportBudget = 16 * 1024 * 1024;
const itemLimit = 96;

export function createReportSession() {
  const files = new Map();
  const operations = [];
  const omitted = { files: 0, operations: 0 };
  let remaining = reportBudget;
  const key = node => JSON.stringify(node.route);
  const describe = node => ({ route: node.route, path: node.path });
  const sizeOf = value => JSON.stringify(value).length;

  return {
    retainFile(node) {
      const id = key(node);
      if (!node.route.length) return;
      const previous = files.get(id);
      const file = { ...describe(node), report: { ...previous?.file.report, ...node.report } };
      const size = sizeOf(file);
      const cost = size - (previous?.size ?? 0);
      if (cost > remaining || (!previous && files.size >= itemLimit) || size > reportBudget / 2) {
        omitted.files++;
        return;
      }
      remaining -= cost;
      files.set(id, { file, size });
    },
    record(node, kind, result, input) {
      const entry = { ...describe(node), kind, ...(input ? { input } : {}), result };
      const size = sizeOf(entry);
      if (size > remaining || operations.length >= itemLimit || size > reportBudget / 2) {
        omitted.operations++;
        return result;
      }
      operations.push(entry);
      remaining -= size;
      return result;
    },
    snapshot(root, active, automatic, inventory) {
      const nodes = new Map([...files].map(([id, value]) => [id, value.file]));
      for (const node of [root, active]) {
        const id = key(node);
        nodes.set(id, { ...describe(node), report: { ...nodes.get(id)?.report, ...node.report } });
      }
      return {
        schema: 'gameautopsy/full-report/1', appVersion: root.report.version, createdAt: new Date().toISOString(),
        root: describe(root), active: describe(active), automatic, inventory: inventory ?? null,
        files: [...nodes.values()], operations, omitted: { ...omitted }
      };
    }
  };
}
