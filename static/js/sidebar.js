// Toggle the visibility of a dropdown menu
const toggleDropdown = (dropdown, menu, isOpen) => {
    dropdown.classList.toggle("open", isOpen)
    menu.style.height = isOpen ? `${menu.scrollHeight}px` : 0;
}

// Close all open dropdowns
const closeAllDropdowns = () => {
    document.querySelectorAll(".sb-dropdown-container.open").forEach(openDropdown => {
        toggleDropdown(openDropdown, openDropdown.querySelector(".sb-dropdown-menu"), false);
    });
}

// Attach click event to all dropdown toggles
document.querySelectorAll(".sb-dropdown-toggle").forEach(dropdownToggle => {
    dropdownToggle.addEventListener("click", e => {
        e.preventDefault();

        const dropdown = e.target.closest(".sb-dropdown-container");
        const menu = dropdown.querySelector(".sb-dropdown-menu");
        const isOpen = dropdown.classList.contains("open");

        closeAllDropdowns(); // Close all open dropdowns

        toggleDropdown(dropdown, menu, !isOpen) // Toggle current dropdown visibility

    });
});

// Attach click event to sidebar toggle buttons
document.querySelectorAll(".sidebar-toggler, .sidebar-menu-button").forEach(button => {
    button.addEventListener("click", () => {
        closeAllDropdowns();

        // Toggle collapsed class on sidebar
        document.querySelector(".sidebar").classList.toggle("collapsed");
    });
});

// Collapse sidebar by default on small screens
if (window.innerWidth <= 1024) document.querySelector(".sidebar").classList.toggle("collapsed");