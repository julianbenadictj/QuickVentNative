var topBar = document.querySelector(".topbar-content");

// Hide navigation items in dropdown menu
var navBrand = document.querySelector(".navbar-brand");
var navMenu = document.querySelector(".navbar-nav");
var originalNavElements = [...navMenu.querySelectorAll(".mx-navbar-item")];
var userElem =
  document.querySelector('.mx-navbar-item:has(a[title="Login"])') === null
    ? document.querySelector('.mx-navbar-item:has(a[title=""])')
    : document.querySelector('.mx-navbar-item:has(a[title="Login"])');

var navBrandWidth = navBrand.clientWidth;
var navMenuWidth = navMenu.clientWidth;

var dropdownMenuStructure = `
<li class="mx-navbar-item dropdown dropdown__storage" role="none">
  <a
    class="mx-name-menuBar1-${originalNavElements.length + 1}"
    href="#"
    role="menuitem"
    title="..."
    aria-haspopup="true"
    aria-expanded="false"
    ><span
      class="glyphicon glyphicon-list-alt"
      aria-hidden="true"
    ></span>
    ...
  </a>
  <ul class="dropdown-menu mx-navbar-submenu dropdown-menu__storage" role="menu">
    
  </ul>
</li>
`;
userElem.insertAdjacentHTML("beforebegin", dropdownMenuStructure);

var storageDropdownMenu = navMenu.querySelector(".dropdown__storage");
var dropdownMenu = navMenu.querySelector(".dropdown-menu__storage");
storageDropdownMenu.style.display = "none";
var storageMenuItem = storageDropdownMenu.querySelector('a[title="..."]');

var navItems = document.querySelectorAll(
  ".mx-navbar-item:not(.dropdown__storage)"
);

function addItemToMenu() {
  const [itemToAdd, ...items] = [
    ...navMenu.querySelectorAll(
      ".mx-navbar-item:not(.mx-navbar-item.dropdown)"
    ),
  ]
    .filter(
      (elem) =>
        !elem.firstElementChild.text.includes("Login") ||
        !elem.firstElementChild.text.includes("")
    )
    .reverse();

  if (itemToAdd !== undefined) {
    itemToAdd.classList.remove("mx-navbar-item");
    itemToAdd.classList.add("mx-navbar-subitem");
    dropdownMenu.appendChild(itemToAdd);
    navMenuWidth = navMenu.clientWidth;
    dropdownMenu.hasChildNodes()
      ? (storageDropdownMenu.style.display = "block")
      : null;

    handleNavigation();
  }

  return;
}

function removeItemFromMenu() {
  var indexOfLastItem = null;
  const itemToRemove = dropdownMenu.querySelector(
    ".mx-navbar-subitem:last-child"
  );

  if (itemToRemove !== null) {
    indexOfLastItem = originalNavElements.findIndex(
      (elem) => elem === itemToRemove
    );
    const elem = navMenu.querySelectorAll(".mx-navbar-item")[indexOfLastItem];

    itemToRemove.classList.remove("mx-navbar-subitem");
    itemToRemove.classList.add("mx-navbar-item");

    elem.insertAdjacentElement("beforebegin", itemToRemove);
    navMenuWidth = navMenu.clientWidth;
    !dropdownMenu.querySelectorAll(".mx-navbar-subitem").length
      ? (storageDropdownMenu.style.display = "none")
      : null;
  }

  return;
}

function handleNavigation(e) {
  if (topBar.clientWidth < navBrandWidth + navMenuWidth + 100) {
    addItemToMenu();
  } else if (topBar.clientWidth > navBrandWidth + navMenuWidth + 200) {
    removeItemFromMenu();
  } else {
    return;
  }
}

function handleOpenMenu(e) {
  e.preventDefault();
  storageDropdownMenu.classList.toggle("open");
  storageMenuItem.ariaExpanded =
    storageMenuItem.ariaExpanded === "true" ? "true" : "false";
}

function handleCloseMenu(e) {
  if (!!e.target.closest(".dropdown__storage")) return;

  storageDropdownMenu.classList.remove("open");
  storageMenuItem.ariaExpanded = "false";
}

handleNavigation();

navItems.forEach((item) => item.addEventListener("click", handleCloseMenu));

storageDropdownMenu.addEventListener("click", handleOpenMenu);
window.addEventListener("resize", handleNavigation);
window.addEventListener("click", handleCloseMenu);
