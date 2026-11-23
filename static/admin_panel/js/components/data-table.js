/**
 * مكونات التصفية والفرز والبحث الفوري للجداول المحلية ([data-client-table]).
 */
export function initClientTables() {
    document.querySelectorAll('[data-table-scope]').forEach((scope) => {
        const table = scope.querySelector('table');
        if (!table) return;
        const tbody = table.querySelector('tbody');
        const searchInput = scope.querySelector('[data-table-search]');
        const pillButtons = scope.querySelectorAll('[data-filter-pill]');
        const emptyRow = scope.querySelector('[data-client-empty]');

        let currentStatus = 'all';
        let currentQuery = '';

        const applyFilter = () => {
            const rows = tbody ? Array.from(tbody.querySelectorAll('tr[data-row]')) : [];
            let visibleCount = 0;

            rows.forEach((row) => {
                const rowStatus = row.dataset.status || '';
                const rowText = (row.textContent || '').toLowerCase();
                const matchesStatus = currentStatus === 'all' || rowStatus === currentStatus;
                const matchesQuery = !currentQuery || rowText.includes(currentQuery);
                const visible = matchesStatus && matchesQuery;
                row.classList.toggle('ap-hidden', !visible);
                if (visible) visibleCount += 1;
            });

            if (emptyRow) {
                emptyRow.classList.toggle('ap-hidden', visibleCount > 0 || rows.length === 0);
            }
        };

        if (searchInput) {
            searchInput.addEventListener('input', () => {
                currentQuery = searchInput.value.trim().toLowerCase();
                applyFilter();
            });
        }

        pillButtons.forEach((pill) => {
            pill.addEventListener('click', () => {
                pillButtons.forEach((b) => b.classList.remove('active'));
                pill.classList.add('active');
                currentStatus = pill.dataset.filterPill || 'all';
                applyFilter();
            });
        });

        scope.querySelectorAll('thead th[data-sort-col]').forEach((th) => {
            th.setAttribute('data-sort', '1');
            let asc = true;
            th.addEventListener('click', () => {
                if (!tbody) return;
                const colIndex = Number(th.dataset.sortCol);
                const rows = Array.from(tbody.querySelectorAll('tr[data-row]'));
                rows.sort((a, b) => {
                    const aCell = a.children[colIndex];
                    const bCell = b.children[colIndex];
                    const aVal = aCell?.dataset.sortVal ?? aCell?.textContent.trim() ?? '';
                    const bVal = bCell?.dataset.sortVal ?? bCell?.textContent.trim() ?? '';
                    const aNum = Number(aVal);
                    const bNum = Number(bVal);
                    if (!Number.isNaN(aNum) && !Number.isNaN(bNum) && aVal !== '' && bVal !== '') {
                        return asc ? aNum - bNum : bNum - aNum;
                    }
                    return asc ? aVal.localeCompare(bVal, 'ar') : bVal.localeCompare(aVal, 'ar');
                });
                asc = !asc;
                rows.forEach((r) => tbody.appendChild(r));
            });
        });
    });
}
