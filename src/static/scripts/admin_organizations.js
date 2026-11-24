"use strict";
/* global DataTable, _post:readable, BASE_URL:readable, reload:readable, jdenticon:readable, confirmDanger:readable */

async function deleteOrganization(event) {
    event.preventDefault();
    event.stopPropagation();
    const org_uuid = event.target.dataset.vwOrgUuid;
    const org_name = event.target.dataset.vwOrgName;
    const billing_email = event.target.dataset.vwBillingEmail;
    if (!org_uuid) {
        alert("缺少必要参数。");
        return false;
    }

    const confirmed = await confirmDanger({
        title: `删除组织 ${org_name}`,
        body: `组织的全部数据会丢失，无法撤销。账单邮箱：${billing_email || "无"}。请输入组织 ID 以确认。`,
        confirmLabel: "删除组织",
        expect: org_uuid,
        expectLabel: "输入组织 ID"
    });
    if (confirmed) {
        _post(`${BASE_URL}/admin/organizations/${org_uuid}/delete`,
            "组织已删除",
            "删除组织失败"
        );
    }
}

function initActions() {
    document.querySelectorAll("button[vw-delete-organization]").forEach(btn => {
        btn.addEventListener("click", deleteOrganization);
    });

    if (jdenticon) {
        jdenticon();
    }
}

// onLoad events
document.addEventListener("DOMContentLoaded", (/*event*/) => {
    const columnCount = document.getElementById("orgs-table").querySelectorAll("thead th").length;
    new DataTable("#orgs-table", {
        "drawCallback": function () {
            initActions();
        },
        "stateSave": true,
        "responsive": true,
        "lengthMenu": [
            [-1, 5, 10, 25, 50],
            ["全部", 5, 10, 25, 50]
        ],
        "language": {
            "search": "搜索",
            "lengthMenu": "每页 _MENU_ 条",
            "info": "第 _START_–_END_ 条，共 _TOTAL_ 条",
            "infoEmpty": "没有记录",
            "zeroRecords": "没有匹配的记录",
            "paginate": { "first": "首页", "last": "末页", "next": "下页", "previous": "上页" }
        },
        "pageLength": -1, // Default show all
        "columnDefs": [{
            "targets": [columnCount - 2, columnCount - 1], // Do not include the last two columns into the search/order features
            "searchable": false,
            "orderable": false
        }]
    });

    // Add click events for organization actions
    initActions();

    const btnReload = document.getElementById("reload");
    if (btnReload) {
        btnReload.addEventListener("click", reload);
    }
});
