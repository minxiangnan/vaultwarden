"use strict";
/* global DataTable, _post:readable, _delete:readable, BASE_URL:readable, reload:readable, jdenticon:readable, confirmDanger:readable */

async function deleteUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("缺少必要参数。");
        return false;
    }
    const confirmed = await confirmDanger({
        title: `删除用户 ${email}`,
        body: "删除后该账户及其数据无法恢复。请输入该用户的邮箱以确认。",
        confirmLabel: "删除用户",
        expect: email,
        expectLabel: "输入邮箱"
    });
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/delete`,
            "用户已删除",
            "删除用户失败"
        );
    }
}

async function deleteSSOUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("缺少必要参数。");
        return false;
    }
    const confirmed = await confirmDanger({
        title: `删除 SSO 关联 ${email}`,
        body: "只删除单点登录关联，账户仍会保留。请输入该用户的邮箱以确认。",
        confirmLabel: "删除关联",
        expect: email,
        expectLabel: "输入邮箱"
    });
    if (confirmed) {
        _delete(`${BASE_URL}/admin/users/${id}/sso`,
            "SSO 关联已删除",
            "删除 SSO 关联失败"
        );
    }
}

async function remove2fa(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("缺少必要参数。");
        return false;
    }
    const confirmed = await confirmDanger({
        title: `移除二次验证 ${email}`,
        body: "会移除该用户的全部二次验证。",
        confirmLabel: "移除二次验证"
    });
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/remove-2fa`,
            "二次验证已移除",
            "移除二次验证失败"
        );
    }
}

async function revokeMcp(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("缺少必要参数。");
        return false;
    }
    const confirmed = await confirmDanger({
        title: `吊销 MCP 令牌 ${email}`,
        body: "已放行的验证码会立刻停止读取，直到用户创建新令牌。",
        confirmLabel: "吊销令牌"
    });
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/revoke-mcp`,
            "MCP 令牌已吊销",
            "吊销 MCP 令牌失败"
        );
    }
}

async function deauthUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("缺少必要参数。");
        return false;
    }
    const confirmed = await confirmDanger({
        title: `注销会话 ${email}`,
        body: "该用户当前的登录会话会立即失效。",
        confirmLabel: "注销会话"
    });
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/deauth`,
            "会话已注销",
            "注销会话失败"
        );
    }
}

async function disableUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("缺少必要参数。");
        return false;
    }
    const confirmed = await confirmDanger({
        title: `停用用户 ${email}`,
        body: "停用后会同时注销该用户的会话。",
        confirmLabel: "停用用户"
    });
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/disable`,
            "用户已停用",
            "停用用户失败"
        );
    }
}

async function enableUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("缺少必要参数。");
        return false;
    }
    const confirmed = await confirmDanger({
        title: `启用用户 ${email}`,
        body: "启用后该用户可以重新登录。",
        confirmLabel: "启用用户"
    });
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/enable`,
            "用户已启用",
            "启用用户失败"
        );
    }
}

function updateRevisions(event) {
    event.preventDefault();
    event.stopPropagation();
    _post(`${BASE_URL}/admin/users/update_revision`,
        "Success, clients will sync next time they connect",
        "Error forcing clients to sync"
    );
}

function inviteUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const email = document.getElementById("inviteEmail");
    const data = JSON.stringify({
        "email": email.value
    });
    email.value = "";
    _post(`${BASE_URL}/admin/invite`,
        "User invited correctly",
        "Error inviting user",
        data
    );
}

async function resendUserInvite(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("缺少必要参数。");
        return false;
    }
    const confirmed = await confirmDanger({
        title: `重发邀请 ${email}`,
        body: "将再次向该邮箱发送邀请。",
        confirmLabel: "重发邀请"
    });
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/invite/resend`,
            "邀请已发送",
            "重发邀请失败"
        );
    }
}

const ORG_TYPES = {
    "0": {
        "name": "Owner",
        "bg": "orange",
        "font": "black"
    },
    "1": {
        "name": "Admin",
        "bg": "blueviolet"
    },
    "2": {
        "name": "User",
        "bg": "blue"
    },
    "3": {
        "name": "Manager",
        "bg": "green"
    },
    "4": {
        "name": "Custom",
        "bg": "teal"
    },
};

const userOrgTypeDialog = document.getElementById("userOrgTypeDialog");
// Fill the form and title
userOrgTypeDialog.addEventListener("show.bs.modal", function (event) {
    // Get shared values
    const userEmail = event.relatedTarget.parentNode.dataset.vwUserEmail;
    const userUuid = event.relatedTarget.parentNode.dataset.vwUserUuid;
    // Get org specific values
    const userOrgType = event.relatedTarget.dataset.vwOrgType;
    const orgName = event.relatedTarget.dataset.vwOrgName;
    const orgUuid = event.relatedTarget.dataset.vwOrgUuid;

    document.getElementById("userOrgTypeForm").reset();
    document.getElementById("userOrgTypeDialogOrgName").textContent = orgName;
    document.getElementById("userOrgTypeDialogUserEmail").textContent = userEmail;
    document.getElementById("userOrgTypeUserUuid").value = userUuid;
    document.getElementById("userOrgTypeOrgUuid").value = orgUuid;
    // The Custom role can only be selected while it is enabled
    const userOrgTypeRadio = document.getElementById(`userOrgType${ORG_TYPES[userOrgType]?.name}`);
    if (userOrgTypeRadio) {
        userOrgTypeRadio.checked = true;
    }
}, false);

// Prevent accidental submission of the form with valid elements after the modal has been hidden.
userOrgTypeDialog.addEventListener("hide.bs.modal", function () {
    document.getElementById("userOrgTypeDialogOrgName").textContent = "";
    document.getElementById("userOrgTypeDialogUserEmail").textContent = "";
    document.getElementById("userOrgTypeUserUuid").value = "";
    document.getElementById("userOrgTypeOrgUuid").value = "";
}, false);

function updateUserOrgType(event) {
    event.preventDefault();
    event.stopPropagation();

    const data = JSON.stringify(Object.fromEntries(new FormData(event.target).entries()));

    _post(`${BASE_URL}/admin/users/org_type`,
        "Updated organization type of the user successfully",
        "Error updating organization type of the user",
        data
    );
}

function initUserTable() {
    // Color all the org buttons per type
    document.querySelectorAll("button[data-vw-org-type]").forEach(function (e) {
        const orgType = ORG_TYPES[e.dataset.vwOrgType] ?? { "name": "Unknown", "bg": "gray" };
        e.style.backgroundColor = orgType.bg;
        if (orgType.font !== undefined) {
            e.style.color = orgType.font;
        }
        e.title = orgType.name;
    });

    document.querySelectorAll("button[vw-remove2fa]").forEach(btn => {
        btn.addEventListener("click", remove2fa);
    });
    document.querySelectorAll("button[vw-deauth-user]").forEach(btn => {
        btn.addEventListener("click", deauthUser);
    });
    document.querySelectorAll("button[vw-revoke-mcp]").forEach(btn => {
        btn.addEventListener("click", revokeMcp);
    });
    document.querySelectorAll("button[vw-delete-user]").forEach(btn => {
        btn.addEventListener("click", deleteUser);
    });
    document.querySelectorAll("button[vw-delete-sso-user]").forEach(btn => {
        btn.addEventListener("click", deleteSSOUser);
    });
    document.querySelectorAll("button[vw-disable-user]").forEach(btn => {
        btn.addEventListener("click", disableUser);
    });
    document.querySelectorAll("button[vw-enable-user]").forEach(btn => {
        btn.addEventListener("click", enableUser);
    });
    document.querySelectorAll("button[vw-resend-user-invite]").forEach(btn => {
        btn.addEventListener("click", resendUserInvite);
    });

    if (jdenticon) {
        jdenticon();
    }
}

// Special sort function to sort dates in ISO format and have anything else as 0
DataTable.ext.type.order["date-iso-pre"] = function (a) {
    let x;
    const sortDate = a.replace(/(<([^>]+)>)/gi, "").trim();
    if (sortDate !== "") {
        const dtParts = sortDate.split(" ");
        const timeParts = (undefined != dtParts[1]) ? dtParts[1].split(":") : ["00", "00", "00"];
        const dateParts = dtParts[0].split("-");
        x = (dateParts[0] + dateParts[1] + dateParts[2] + timeParts[0] + timeParts[1] + ((undefined != timeParts[2]) ? timeParts[2] : 0)) * 1;
        if (isNaN(x)) {
            x = 0;
        }
    } else {
        x = Infinity;
    }
    return x;
};

// onLoad events
document.addEventListener("DOMContentLoaded", (/*event*/) => {
    DataTable.ext.type.detect.unshift(function (data) {
        if (typeof data !== "string") { return null; }
        return data.indexOf("data-sort-type=\"date-iso\"") !== -1
            ? "date-iso"
            : null;
    });

    const columnCount = document.getElementById("users-table").querySelectorAll("thead th").length;
    new DataTable("#users-table", {
        "typeDetect": true,
        "drawCallback": function () {
            initUserTable();
        },
        "stateSave": true,
        "responsive": true,
        "lengthMenu": [
            [-1, 2, 5, 10, 25, 50],
            ["全部", 2, 5, 10, 25, 50]
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
            "targets": columnCount - 1, // Do not include the last column into the search/order features
            "searchable": false,
            "orderable": false
        }]
    });

    // Add click events for user actions
    initUserTable();

    const btnUpdateRevisions = document.getElementById("updateRevisions");
    if (btnUpdateRevisions) {
        btnUpdateRevisions.addEventListener("click", updateRevisions);
    }
    const btnReload = document.getElementById("reload");
    if (btnReload) {
        btnReload.addEventListener("click", reload);
    }
    const btnUserOrgTypeForm = document.getElementById("userOrgTypeForm");
    if (btnUserOrgTypeForm) {
        btnUserOrgTypeForm.addEventListener("submit", updateUserOrgType);
    }
    const btnInviteUserForm = document.getElementById("inviteUserForm");
    if (btnInviteUserForm) {
        btnInviteUserForm.addEventListener("submit", inviteUser);
    }
});
