import {css, html, LitElement, unsafeCSS} from "lit";
import {customElement, property, state} from "lit/decorators.js";
import "./or-dashboard-tree";
import "./or-dashboard-browser";
import "./or-dashboard-preview";
import "./or-dashboard-widgetsettings";
import "./or-dashboard-boardsettings";
import {InputType, OrInputChangedEvent} from '@openremote/or-mwc-components/or-mwc-input';
import "@openremote/or-icon";
import {style} from "./style";
import {ORGridStackNode} from "./or-dashboard-preview";
import {
    ClientRole,
    Dashboard,
    DashboardAccess,
    DashboardGridItem,
    DashboardScalingPreset,
    DashboardScreenPreset,
    DashboardTemplate,
    DashboardWidget,
    DashboardWidgetType
} from "@openremote/model";
import manager, {DefaultColor3, DefaultColor5} from "@openremote/core";
import {getContentWithMenuTemplate} from "@openremote/or-mwc-components/or-mwc-menu";
import {ListItem} from "@openremote/or-mwc-components/or-mwc-list";
import {OrMwcTabItem} from "@openremote/or-mwc-components/or-mwc-tabs";
import "@openremote/or-mwc-components/or-mwc-tabs";
import {showSnackbar} from "@openremote/or-mwc-components/or-mwc-snackbar";
import {i18next} from "@openremote/or-translate";

// language=CSS
const styling = css`

    #tree {
        flex-shrink: 0;
        align-items: stretch;
        z-index: 1;
        max-width: 300px;
        box-shadow: rgb(0 0 0 / 21%) 0px 1px 3px 0px;
    }
    
    /* Header related styling */
    #header {
        display: table-row;
        height: 1px;
        background: white;
    }
    #header-wrapper {
        padding: 20px 20px 14px 20px;
        display: flex;
        flex-direction: row;
        align-items: center;
        border-bottom: 1px solid #E0E0E0;
    }
    #header-title {
        font-size: 18px;
    }
    #header-title > or-icon {
        margin-right: 10px;
    }
    #header-actions {
        flex: 1 1 auto;
        text-align: right;
    }
    #header-actions-content {
        display: flex;
        flex-direction: row;
        align-items: center;
        float: right;
    }

    /* Header related styling */
    #fullscreen-header {
        display: table-row;
        height: 1px;
    }
    #fullscreen-header-wrapper {
        padding: 17.5px 20px;
        display: flex;
        flex-direction: row;
        align-items: center;
    }
    #fullscreen-header-title {
        font-size: 18px;
        font-weight: bold;
    }
    #fullscreen-header-title > or-mwc-input {
        margin-right: 4px;
        --or-icon-fill: ${unsafeCSS(DefaultColor3)};
    }
    #fullscreen-header-actions {
        flex: 1 1 auto;
        text-align: right;
    }
    #fullscreen-header-actions-content {
        display: flex;
        flex-direction: row;
        align-items: center;
        float: right;
    }
    
    /* ----------------------------- */
    /* Editor/builder related styling */
    #builder {
        flex: 1 0 auto;
        height: 100%;
    }
    
    /* ----------------------------- */
    /* Sidebar related styling (drag and drop widgets / configuration) */
    #sidebar {
        vertical-align: top;
        position: relative;
        width: 300px;
        background: white;
        border-left: 1px solid #E0E0E0;
    }
    .settings-container {
        display: flex;
        flex-direction: column;
        height: 100%;
    }
    #browser {
        flex-grow: 1;
        align-items: stretch;
        z-index: 1;
        max-width: 300px;
    }
    
    #save-btn { margin-left: 15px; }
    #view-btn { margin-left: 15px; }
    
    .hidescroll {
        -ms-overflow-style: none; /* for Internet Explorer, Edge */
        scrollbar-width: none; /* for Firefox */
    }
    .hidescroll::-webkit-scrollbar {
        display: none; /* for Chrome, Safari, and Opera */
    }
`;

export interface DashboardBuilderConfig {
    // no configuration built yet
}
export const MAX_BREAKPOINT = 1000000;

// Enum to Menu String method
export function scalingPresetToString(scalingPreset: DashboardScalingPreset | undefined): string {
    return (scalingPreset != null ? i18next.t("dashboard.presets." + scalingPreset.toLowerCase()) : "undefined");
}
export function dashboardAccessToString(access: DashboardAccess): string {
    return i18next.t("dashboard.access." + access.toLowerCase());
}

export function sortScreenPresets(presets: DashboardScreenPreset[], largetosmall: boolean = false): DashboardScreenPreset[] {
    return presets.sort((a, b) => {
        if(a.breakpoint != null && b.breakpoint != null) {
            if(a.breakpoint > b.breakpoint) {
                return (largetosmall ? 1 : -1);
            }
            if(a.breakpoint < b.breakpoint) {
                return (largetosmall ? 1 : -1);
            }
        }
        return 0;
    });
}

export function getActivePreset(gridWidth: number, presets: DashboardScreenPreset[]): DashboardScreenPreset | undefined {
    let activePreset: DashboardScreenPreset | undefined;
    sortScreenPresets(presets, true).forEach((preset) => {
        if(preset.breakpoint != null && gridWidth <= preset.breakpoint) {
            activePreset = preset;
        }
    });
    return activePreset;
}


@customElement("or-dashboard-builder")
export class OrDashboardBuilder extends LitElement {

    // Importing Styles; the unsafe GridStack css, and all custom css
    static get styles() {
        return [styling, style]
    }

    @property()
    protected readonly config: DashboardBuilderConfig | undefined;

    @property() // Originally from URL
    protected readonly editMode: boolean | undefined;

    @property() // Originally from URL
    protected readonly selectedId: string | undefined;

    @property() // Originally just manager.displayRealm
    protected realm: string | undefined;

    @property() // REQUIRED userId
    protected userId: string | undefined;

    @property()
    protected readonly: boolean = true;


    /* ------------------- */

    @state()
    protected dashboards: Dashboard[] | undefined;

    @state() // Separate local template object
    protected currentTemplate: DashboardTemplate | undefined;

    @state()
    protected selectedDashboard: Dashboard | undefined;

    @state()
    protected selectedWidget: DashboardWidget | undefined;

    @state() // Used to toggle the SAVE button depending on whether changes have been made.
    protected initialDashboardJSON: string | undefined;

    @state() // Used to toggle the SAVE button depending on whether changes have been made.
    protected initialTemplateJSON: string | undefined;

    @state()
    protected isInitializing: boolean;

    @state()
    protected isLoading: boolean;

    @state() // Whether changes have been made
    protected hasChanged: boolean;

    @state()
    protected rerenderPending: boolean;


    /* ------------- */

    constructor() {
        super();
        this.isInitializing = true;
        this.isLoading = true;
        this.hasChanged = false;
        this.rerenderPending = false;

        this.updateComplete.then(async () => {
            await this.updateDashboards(this.realm!);
        });
    }

    async updateDashboards(realm: string) {

        // Getting dashboards
        await manager.rest.api.DashboardResource.getAllRealmDashboards(realm).then((result) => {
            this.dashboards = result.data;
        }).catch((reason) => {
            showSnackbar(undefined, i18next.t('errorOccurred'));
            console.error(reason);
        });

        // Setting dashboard if selectedId is given by parent component
        if(this.selectedId != undefined) {
            this.selectedDashboard = Object.assign({}, this.dashboards?.find(x => { return x.id == this.selectedId; }));
        }
    }

    /* ------------- */

    // On every property update
    updated(changedProperties: Map<string, any>) {
        console.log(changedProperties);
        this.isLoading = (this.dashboards == undefined);
        this.isInitializing = (this.dashboards == undefined);
        if(this.realm == undefined) { this.realm = manager.displayRealm; }

        // On any update (except widget selection), check whether hasChanged should be updated.
        if(!(changedProperties.size == 1 && changedProperties.has('selectedWidget'))) {
            this.hasChanged = (JSON.stringify(this.selectedDashboard) != this.initialDashboardJSON || JSON.stringify(this.currentTemplate) != this.initialTemplateJSON);
        }

        // Support for realm switching
        if(changedProperties.has("realm") && changedProperties.get("realm") != undefined) {
            this.updateDashboards(this.realm);
        }

        // Any update on the dashboard
        if(changedProperties.has("selectedDashboard")) {
            this.selectedWidget = undefined;
            this.currentTemplate = this.selectedDashboard?.template;
            this.dispatchEvent(new CustomEvent("selected", { detail: this.selectedDashboard }))
        }

        // Update on the Grid and its widget
        if(changedProperties.has("currentTemplate")) {
            if(this.selectedDashboard != null) {
                this.selectedDashboard.template = this.currentTemplate;
            }
        }
        // When edit/view mode gets toggled
        if(changedProperties.has("editMode")) {
            this.selectedWidget = undefined;
            this.showDashboardTree = true;
        }
    }

    /* ----------------- */

    // Method for creating Widgets (reused at many places)
    createWidget(gridStackNode: ORGridStackNode): DashboardWidget {
        const randomId = (Math.random() + 1).toString(36).substring(2);
        let displayName = generateWidgetDisplayName(this.currentTemplate!, gridStackNode.widgetType);
        if(displayName == undefined) { displayName = (i18next.t('widget') + " #" + randomId); } // If no displayName, set random ID as name.
        const gridItem: DashboardGridItem = generateGridItem(gridStackNode, displayName);

        const widget = {
            id: randomId,
            displayName: displayName,
            gridItem: gridItem,
            widgetType: gridStackNode.widgetType
        } as DashboardWidget;

        const tempTemplate = this.currentTemplate;
        tempTemplate?.widgets?.push(widget);
        this.currentTemplate = Object.assign({}, tempTemplate); // Force property update
        return widget;
    }

    deleteWidget(widget: DashboardWidget) {
        if(this.currentTemplate != null && this.currentTemplate.widgets != null) {
            const tempTemplate = this.currentTemplate;
            tempTemplate.widgets = tempTemplate.widgets?.filter((x: DashboardWidget) => { return x.id != widget.id; });
            this.currentTemplate = Object.assign({}, tempTemplate);
        }
        if(this.selectedWidget?.id == widget.id) {
            this.deselectWidget();
        }
    }

    /* ------------------------------ */

    selectWidget(widget: DashboardWidget): void {
        const foundWidget = this.currentTemplate?.widgets?.find((x) => { return x.gridItem?.id == widget.gridItem?.id; });
        if(foundWidget != null) {
            this.selectedWidget = foundWidget;
        } else {
            console.error("The selected widget does not exist!");
        }
    }
    deselectWidget() {
        this.selectedWidget = undefined;
    }

    /* --------------------- */

    selectDashboard(dashboard: Dashboard | undefined) {
        if(this.dashboards != null) {
            if(this.selectedDashboard && this.initialDashboardJSON) {
                const indexOf = this.dashboards.indexOf(this.selectedDashboard);
                if(indexOf) {
                    this.dashboards[indexOf] = JSON.parse(this.initialDashboardJSON) as Dashboard;
                }
            }
            this.selectedDashboard = (dashboard ? this.dashboards.find((x) => { return x.id == dashboard.id; }) : undefined);
            this.initialDashboardJSON = JSON.stringify(this.selectedDashboard);
            this.initialTemplateJSON = JSON.stringify(this.selectedDashboard?.template);
        }
    }

    changeDashboardName(value: string) {
        if(this.selectedDashboard != null) {
            const dashboard = this.selectedDashboard;
            dashboard.displayName = value;
            this.selectedDashboard = Object.assign({}, dashboard);
        }
    }

    shareUrl(method: string) {
        let url = window.location.href.replace("true", "false");
        if(method == 'copy') {
            navigator.clipboard.writeText(url);
        } else if(method == 'tab') {
            window.open(url, '_blank')?.focus()
        }
    }

    /* ----------------------------------- */

    saveDashboard() {
        if(this.selectedDashboard != null) {
            this.isLoading = true;

            // Saving object into the database
            manager.rest.api.DashboardResource.update(this.selectedDashboard).then(() => {
                if(this.dashboards != null && this.selectedDashboard != null) {
                    this.initialDashboardJSON = JSON.stringify(this.selectedDashboard);
                    this.initialTemplateJSON = JSON.stringify(this.selectedDashboard.template);
                    this.dashboards[this.dashboards?.indexOf(this.selectedDashboard)] = this.selectedDashboard;
                    this.currentTemplate = Object.assign({}, this.selectedDashboard.template);
                    showSnackbar(undefined, i18next.t('dashboard.saveSuccessful'));
                }
            }).catch((reason) => {
                console.error(reason);
                showSnackbar(undefined, i18next.t('errorOccurred'));
            }).finally(() => {
                this.isLoading = false;
            })
        } else {
            console.error("The selected dashboard could not be found..");
            showSnackbar(undefined, i18next.t('errorOccurred'));
        }
    }

    protected _isReadonly(): boolean {
        return this.readonly || !manager.hasRole(ClientRole.WRITE_INSIGHTS);
    }
    protected _hasEditAccess(): boolean {
        return this.userId != null && (this.selectedDashboard?.editAccess == DashboardAccess.PRIVATE ? this.selectedDashboard?.ownerId == this.userId : true)
    }
    protected _hasViewAccess(): boolean {
        return this.userId != null && (this.selectedDashboard?.viewAccess == DashboardAccess.PRIVATE ? this.selectedDashboard?.ownerId == this.userId : true)
    }

    /* ----------------- */

    @state()
    protected sidebarMenuIndex: number = 0;

    @state()
    protected showDashboardTree: boolean = true;

    // Rendering the page
    render(): any {
        const menuItems: ListItem[] = [
            { icon: "content-copy", text: (i18next.t("copy") + " URL"), value: "copy" },
            { icon: "open-in-new", text: i18next.t("dashboard.openInNewTab"), value: "tab" },
        ];
        const tabItems: OrMwcTabItem[] = [
            { name: i18next.t("dashboard.widgets") }, { name: i18next.t("settings") }
        ];
        return (!this.isInitializing || (this.dashboards != null && this.dashboards.length == 0)) ? html`
            <div id="container">
                ${this.showDashboardTree ? html`
                    <or-dashboard-tree id="tree" .realm="${this.realm}" .hasChanged="${this.hasChanged}" .selected="${this.selectedDashboard}" .dashboards="${this.dashboards}" .showControls="${true}" .userId="${this.userId}"
                                       @created="${(event: CustomEvent) => { this.dispatchEvent(new CustomEvent('editToggle', { detail: true })); }}"
                                       @updated="${(event: CustomEvent) => { this.dashboards = event.detail; this.selectedDashboard = undefined; }}"
                                       @select="${(event: CustomEvent) => { this.selectDashboard(event.detail); }}"
                    ></or-dashboard-tree>
                ` : undefined}
                <div id="container" style="display: table;">
                    ${this.editMode ? html`
                        <div id="header">
                            <div id="header-wrapper">
                                <div id="header-title">
                                    <or-icon icon="view-dashboard"></or-icon>
                                    <or-mwc-input type="${InputType.TEXT}" min="1" max="1023" comfortable required outlined label="${i18next.t('name')}" ?readonly="${this._isReadonly()}"
                                                  .value="${this.selectedDashboard != null ? this.selectedDashboard.displayName : ' '}"
                                                  .disabled="${this.isLoading || (this.selectedDashboard == null)}" 
                                                  @or-mwc-input-changed="${(event: OrInputChangedEvent) => { this.changeDashboardName(event.detail.value); }}"
                                                  style="min-width: 320px;">
                                        
                                    </or-mwc-input>
                                </div>
                                <div id="header-actions">
                                    <div id="header-actions-content">
                                        ${getContentWithMenuTemplate(
                                                html`<or-mwc-input id="share-btn" .disabled="${this.isLoading || (this.selectedDashboard == null)}" type="${InputType.BUTTON}" icon="share-variant"></or-mwc-input>`,
                                                menuItems, "monitor", (method: any) => { this.shareUrl(method); }
                                        )}
                                        <or-mwc-input id="save-btn" ?hidden="${this._isReadonly() || !this._hasEditAccess()}" .disabled="${this.isLoading || !this.hasChanged || (this.selectedDashboard == null)}" type="${InputType.BUTTON}" raised label="${i18next.t('save')}" @or-mwc-input-changed="${() => { this.saveDashboard(); }}"></or-mwc-input>
                                        <or-mwc-input id="view-btn" ?hidden="${this._isReadonly() || !this._hasViewAccess()}" type="${InputType.BUTTON}" outlined icon="eye" label="${i18next.t('viewAsset')}" @or-mwc-input-changed="${() => { this.dispatchEvent(new CustomEvent('editToggle', { detail: false })); }}"></or-mwc-input>
                                    </div>
                                </div>
                            </div>
                        </div>
                    ` : html`
                        <div id="fullscreen-header">
                            <div id="fullscreen-header-wrapper">
                                <div id="fullscreen-header-title">
                                    <or-mwc-input type="${InputType.BUTTON}" icon="menu" @or-mwc-input-changed="${() => { this.showDashboardTree = !this.showDashboardTree; }}"></or-mwc-input>   
                                    <span>${this.selectedDashboard?.displayName}</span>
                                </div>
                                <div id="fullscreen-header-actions">
                                    <div id="fullscreen-header-actions-content">
                                        ${getContentWithMenuTemplate(
                                                html`<or-mwc-input id="share-btn" .disabled="${this.isLoading || (this.selectedDashboard == null)}" type="${InputType.BUTTON}" icon="share-variant"></or-mwc-input>`,
                                                menuItems, "monitor", (method: any) => { this.shareUrl(method); }
                                        )}
                                        <or-mwc-input id="view-btn" ?hidden="${this._isReadonly() || !this._hasEditAccess()}" type="${InputType.BUTTON}" outlined icon="pencil" label="${i18next.t('editAsset')}"
                                                      @or-mwc-input-changed="${() => { this.dispatchEvent(new CustomEvent('editToggle', { detail: true })); }}"></or-mwc-input>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `}
                    <div id="content">
                        <div id="container">
                            ${(this.editMode && (this._isReadonly() || !this._hasEditAccess())) ? html`
                                <div style="display: flex; justify-content: center; align-items: center; height: 100%;">
                                    <span>${!this._hasEditAccess() ? i18next.t('noDashboardWriteAccess') : i18next.t('errorOccurred')}.</span>
                                </div>
                            ` : undefined}
                            <div id="builder" style="${(this.editMode && (this._isReadonly() || !this._hasEditAccess())) ? 'display: none' : undefined}">
                                ${(this.selectedDashboard != null) ? html`
                                    <or-dashboard-preview class="editor" style="background: transparent;"
                                                          .realm="${this.realm}" .template="${this.currentTemplate}"
                                                          .selectedWidget="${this.selectedWidget}" .editMode="${this.editMode}"
                                                          .fullscreen="${!this.editMode}" .readonly="${this._isReadonly()}"
                                                          @selected="${(event: CustomEvent) => { this.selectWidget(event.detail); }}"
                                                          @changed="${(event: CustomEvent) => { this.currentTemplate = event.detail.template; }}"
                                                          @deselected="${() => { this.deselectWidget(); }}"
                                    ></or-dashboard-preview>
                                ` : html`
                                        <div style="display: flex; justify-content: center; align-items: center; height: 100%;">
                                            <span>${i18next.t('noDashboardSelected')}</span>
                                        </div>
                                    `}
                            </div>
                            ${(this.selectedDashboard != null && this.editMode && !this._isReadonly() && this._hasEditAccess()) ? html`
                                <div id="sidebar">
                                    ${this.selectedWidget != null ? html`
                                        <div class="settings-container">
                                            <div id="menu-header">
                                                <div id="title-container">
                                                    <span id="title">${this.selectedWidget?.displayName}:</span>
                                                </div>
                                                <div>
                                                    <or-mwc-input type="${InputType.BUTTON}" icon="close" @or-mwc-input-changed="${() => { this.deselectWidget(); }}"></or-mwc-input>
                                                </div>
                                            </div>
                                            <div id="content" class="hidescroll" style="flex: 1; overflow: hidden auto;">
                                                <div style="position: relative;">
                                                    <or-dashboard-widgetsettings style="position: absolute;" .selectedWidget="${this.selectedWidget}"
                                                                                 @delete="${(event: CustomEvent) => { this.deleteWidget(event.detail); }}"
                                                                                 @update="${() => { this.currentTemplate = Object.assign({}, this.selectedDashboard?.template); }}"
                                                    ></or-dashboard-widgetsettings>
                                                </div>
                                            </div>
                                        </div>
                                    ` : undefined}
                                    <div class="settings-container" style="${this.selectedWidget != null ? css`display: none` : null}">
                                        <div style="border-bottom: 1px solid ${unsafeCSS(DefaultColor5)};">
                                            <or-mwc-tabs .items="${tabItems}" noScroll @activated="${(event: CustomEvent) => { this.sidebarMenuIndex = event.detail.index; }}" style="pointer-events: ${this.selectedDashboard ? undefined : 'none'}"></or-mwc-tabs>
                                        </div>
                                        <div id="content" class="hidescroll" style="flex: 1; overflow: hidden auto;">
                                            <div style="position: relative;">
                                                <or-dashboard-browser id="browser" style="position: absolute; ${this.sidebarMenuIndex != 0 ? css`display: none` : null}"></or-dashboard-browser>
                                                <or-dashboard-boardsettings style="position: absolute; ${this.sidebarMenuIndex != 1 ? css`display: none` : null}" 
                                                                            .dashboard="${this.selectedDashboard}" .showPerms="${this.selectedDashboard?.ownerId == this.userId}" 
                                                                            @update="${(event: CustomEvent) => { this.currentTemplate = Object.assign({}, this.selectedDashboard?.template); (event.detail.force ? this.rerenderPending = true : undefined); }}"
                                                ></or-dashboard-boardsettings>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            ` : undefined}
                        </div>
                    </div>
                </div>
            </div>
        ` : html`
            <div id="container" style="justify-content: center; align-items: center;">
                ${this.isInitializing ? html`
                    <span>${i18next.t("loading")}.</span>
                ` : html`
                    <span>${i18next.t("errorOccurred")}.</span>
                `}
            </div>
        `
    }

    /* ======================== */

}

// Generating the Grid Item details like X and Y coordinates for GridStack to work.
export function generateGridItem(gridstackNode: ORGridStackNode, displayName: string): DashboardGridItem {
    const randomId = (Math.random() + 1).toString(36).substring(2);
    return {
        id: randomId,
        x: gridstackNode.x,
        y: gridstackNode.y,
        w: 2,
        h: 2,
        minW: getWidgetMinWidth(gridstackNode.widgetType),
        minH: getWidgetMinWidth(gridstackNode.widgetType),
        noResize: false,
        noMove: false,
        locked: false,
        // content: this.getWidgetContent(gridstackNode.widgetType, displayName)
    }
}
export function generateWidgetDisplayName(template: DashboardTemplate, widgetType: DashboardWidgetType): string | undefined {
    if(template.widgets != null) {
        const filteredWidgets: DashboardWidget[] = template.widgets.filter((x) => { return x.widgetType == widgetType; });
        switch (widgetType) {
            case DashboardWidgetType.KPI: return (i18next.t('dashboard.widget-kpi') + " #" + (filteredWidgets.length + 1));
            case DashboardWidgetType.LINE_CHART: return (i18next.t('dashboard.widget-linechart') + " #" + (filteredWidgets.length + 1));
        }
    }
    return undefined;
}
export function getWidgetMinWidth(widgetType: DashboardWidgetType): number {
    switch (widgetType) {
        case DashboardWidgetType.LINE_CHART: return 2;
        case DashboardWidgetType.KPI: return 1;
    }
}
