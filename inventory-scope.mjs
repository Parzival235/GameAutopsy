export function filterInventory(rows, query, category) {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return rows.filter(row => {
    if (category && row.category !== category) return false;
    if (!terms.length) return true;
    const text = [...row.path, row.name, row.kind, row.category, row.detectedFormat].join(' ').toLowerCase();
    return terms.every(term => text.includes(term));
  });
}
