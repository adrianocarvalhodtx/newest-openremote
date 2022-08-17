import manager, {DefaultColor4} from "@openremote/core";
import {css, html, LitElement, TemplateResult, unsafeCSS} from "lit";
import {customElement, property, state} from "lit/decorators.js";
import {style} from "./style";
import {
    Asset,
    Attribute,
    AttributeRef,
    DashboardGridItem,
    DashboardScalingPreset,
    DashboardScreenPreset,
    DashboardTemplate,
    DashboardWidget,
    DashboardWidgetType
} from "@openremote/model";
import {
    DashboardSizeOption,
    generateGridItem,
    generateWidgetDisplayName,
    getActivePreset,
    getHeightByPreviewSize,
    getPreviewSizeByPx,
    getWidthByPreviewSize,
    sizeOptionToString,
    stringToSizeOption
} from "./index";
import {InputType, OrInputChangedEvent} from "@openremote/or-mwc-components/or-mwc-input";
import {until} from "lit/directives/until.js";
import {repeat} from 'lit/directives/repeat.js';
import {GridItemHTMLElement, GridStack, GridStackElement, GridStackNode} from "gridstack";

// TODO: Add webpack/rollup to build so consumers aren't forced to use the same tooling
const gridcss = require('gridstack/dist/gridstack.min.css');
const extracss = require('gridstack/dist/gridstack-extra.css');

//language=css
const editorStyling = css`
    
    #view-options {
        padding: 24px;
        display: flex;
        justify-content: center;
        align-items: center;
    }
    /* Margins on view options */
    #fit-btn { margin-right: 10px; }
    #view-preset-select { margin-left: 20px; }
    #width-input { margin-left: 20px; }
    #height-input { margin-left: 10px; }
    #rotate-btn { margin-left: 10px; }
    
    .maingrid {
        border: 3px solid #909090;
        background: #FFFFFF;
        border-radius: 8px;
        overflow-x: hidden;
        overflow-y: scroll;
        padding: 4px;
        position: absolute;
        z-index: 0;
    }
    .maingrid__fullscreen {
        border: none;
        background: transparent;
        border-radius: 0;
        overflow-x: hidden;
        overflow-y: auto;
        height: auto;
        width: 100%;
        padding: 4px;
        /*pointer-events: none;*/
        position: relative;
        z-index: 0;
    }
    .maingrid__disabled {
        pointer-events: none;
        opacity: 40%;
    }
    .grid-stack-item-content {
        background: white;
        box-sizing: border-box;
        border: 2px solid #E0E0E0;
        border-radius: 4px;
        overflow: hidden !important;
    }
    .grid-stack-item-content__active {
        border: 2px solid ${unsafeCSS(DefaultColor4)};    
    }
    .gridItem {
        height: 100%;
        overflow: hidden;
        box-sizing: border-box;
        padding: 8px;
    }
    
    /* Grid lines on the background of the grid */
    .grid-element {
        background-image:
                linear-gradient(90deg, #E0E0E0, transparent 1px),
                linear-gradient(90deg, transparent calc(100% - 1px), #E0E0E0),
                linear-gradient(#E0E0E0, transparent 1px),
                linear-gradient(transparent calc(100% - 1px), #E0E0E0 100%);
    }
`

/* -------------------------------------------------- */

export interface ORGridStackNode extends GridStackNode {
    widgetType: DashboardWidgetType;
}

@customElement("or-dashboard-preview")
export class OrDashboardPreview extends LitElement {

    static get styles() {
        return [unsafeCSS(gridcss), unsafeCSS(extracss), editorStyling, style];
    }

    @property({ hasChanged(oldValue, newValue) { return JSON.stringify(oldValue) != JSON.stringify(newValue); }})
    set template(newValue: DashboardTemplate) {
        const oldValue = this._template;
        if(oldValue != undefined) {
            const changes = {
                changedKeys: Object.keys(newValue).filter(key => (JSON.stringify(newValue[key as keyof DashboardTemplate]) !== JSON.stringify(oldValue[key as keyof DashboardTemplate]))),
                oldValue: oldValue,
                newValue: newValue
            };
            console.log(changes.changedKeys);
            this._template = JSON.parse(JSON.stringify(newValue));
            this.latestChanges = changes;
            this.requestUpdate("template", oldValue);

        } else {
            this._template = newValue;
            console.log("Setting up Grid.. [#1]");
            this.setupGrid(false, false);
        }
    }

    private _template?: DashboardTemplate;

    get template() {
        return this._template!;
    }

    @property() // Optional alternative for template
    protected readonly dashboardId?: string;

    @property() // Normally manager.displayRealm
    protected realm?: string;

    @property({type: Object})
    protected selectedWidget: DashboardWidget | undefined;

    @property()
    protected editMode: boolean = false;

    @property()
    protected previewWidth?: string;

    @property()
    protected previewHeight?: string;

    @property()
    protected previewZoom: number = 1;

    @property() // Optional alternative for previewWidth/previewHeight
    protected previewSize?: DashboardSizeOption;

    @property() // Property that, when toggled on, shows a "loading" state for 200ms, and then renders the component again.
    protected rerenderPending: boolean = false;

    /* -------------- */

    @state()
    protected grid?: GridStack;

    @state() // State where the changes of the template are saved temporarily (for comparison with incoming data)
    protected latestChanges?: {
        changedKeys: string[],
        oldValue: DashboardTemplate,
        newValue: DashboardTemplate
    }

    @state()
    protected activePreset?: DashboardScreenPreset;

    @state()
    protected resizeObserver?: ResizeObserver;

    /* ------------------------------------------- */

    updated(changedProperties: Map<string, any>) { //nosonar
        console.log(changedProperties);
        if(this.realm == undefined) { this.realm = manager.displayRealm; }

        // Setup template (list of widgets and properties)
        if(!this.template && this.dashboardId) {
            manager.rest.api.DashboardResource.get(this.dashboardId).then((response) => { this.template = response.data.template!; });
        } else if(this.template == null && this.dashboardId == null) {
            console.error("Neither the template nor dashboardId attributes have been specified!");
        }

        // If changes to the template have been made
        if(changedProperties.has("latestChanges")) {
            if(this.latestChanges) {

                // If only columns property changed, change columns through the framework and then recreate grid.
                if(this.latestChanges.changedKeys.length == 1 && this.latestChanges.changedKeys.includes('columns') && this.grid) {
                    this.grid.column(this.latestChanges.newValue.columns!);
                    let maingrid = this.shadowRoot?.querySelector(".maingrid");
                    let gridElement = this.shadowRoot?.getElementById("gridElement");
                    gridElement!.style.backgroundSize = "" + this.grid.cellWidth() + "px " + this.grid.getCellHeight() + "px";
                    gridElement!.style.height = maingrid!.scrollHeight + 'px';
                    this.setupGrid(true, false);
                }

                // If ID changed, aka user selected a different template.
                else if(this.latestChanges.changedKeys.includes('id')) {
                    console.log("Setting up Grid.. [#7]");
                    this.setupGrid(true, true);
                }

                // If multiple properties changed, just force rerender all of it.
                else if(this.latestChanges.changedKeys.length > 1) {
                    console.log("Setting up Grid.. [#6]");
                    this.setupGrid(true, true);
                }

                // On widgets change, check whether they are programmatically added to GridStack. If not, adding them.
                else if(this.latestChanges.changedKeys.includes('widgets')) {
                    if(this.grid?.el != null) {
                        this.grid.getGridItems().forEach((gridElement) => {
                            if(!gridElement.classList.contains('ui-draggable')) {
                                this.grid?.makeWidget(gridElement);
                            }
                        })
                    }
                }
                // On screenPreset change, a full force rererender is required
                else if(this.latestChanges.changedKeys.includes('screenPresets')) {
                    console.log("Setting up Grid.. [#3]");
                    this.setupGrid(true, true);
                }
                // Set them to none again
                this.latestChanges = undefined;
            }
        }

        if(changedProperties.has("selectedWidget")) {
            if(this.selectedWidget) {
                if(changedProperties.get("selectedWidget") != undefined) { // if previous selected state was a different widget
                    this.dispatchEvent(new CustomEvent("deselected", { detail: changedProperties.get("selectedWidget") as DashboardWidget }));
                }
                if(this.grid?.el != null) {
                    const foundItem = this.grid?.getGridItems().find((item) => {
                        return item.gridstackNode?.id == this.selectedWidget?.gridItem?.id;
                    });
                    if(foundItem != null) { this.selectGridItem(foundItem); }
                    this.dispatchEvent(new CustomEvent("selected", { detail: this.selectedWidget }));
                }

            } else {
                // Checking whether the mainGrid is not destroyed and there are Items to deselect...
                if(this.grid?.el != undefined && this.grid?.getGridItems() != null) {
                    this.deselectGridItems(this.grid.getGridItems());
                }
                this.dispatchEvent(new CustomEvent("deselected", { detail: changedProperties.get("selectedWidget") as DashboardWidget }));
            }
        }

        // Switching edit/view mode needs recreation of Grid
        if(changedProperties.has("editMode")) {
            console.log("Setting up Grid.. [#4]");
            this.setupGrid(true, false);
        }

        // Adjusting previewSize when manual pixels control changes
        if(changedProperties.has("previewWidth") || changedProperties.has("previewHeight")) {
            this.previewSize = getPreviewSizeByPx(this.previewWidth, this.previewHeight);
        }

        // Adjusting pixels control when previewSize changes.
        if(changedProperties.has("previewSize") && this.previewSize != DashboardSizeOption.CUSTOM) {
            this.previewWidth = getWidthByPreviewSize(this.previewSize);
            this.previewHeight = getHeightByPreviewSize(this.previewSize);
        }

        // When parent component requests a forced rerender
        if(changedProperties.has("rerenderPending")) {
            if(this.rerenderPending) {
                this.rerenderPending = false;
            }
        }
    }


    /* ---------------------------------------- */

    // Wait until function that waits until a boolean returns differently
    waitUntil(conditionFunction: any) {
        const poll = (resolve: any) => {
            if(conditionFunction()) resolve();
            else setTimeout(_ => poll(resolve), 400);
        }
        return new Promise(poll);
    }

    // Main setup Grid method (often used)
    async setupGrid(recreate: boolean, force: boolean = false) { //nosonar
        let gridElement = this.shadowRoot?.getElementById("gridElement");
        if(gridElement != null) {
            console.log("Setting up a new Grid! Using recreate [" + recreate + "] and force [" + force + "].");
            if(recreate && this.grid != null) {
                this.grid.destroy(false);

                if(force) { // Fully rerender the grid by switching rerenderPending on and off, and continue after that.
                    console.log("Recreating the grid after major changes.");
                    this.rerenderPending = true;
                    await this.updateComplete;
                    await this.waitUntil((_: any) => !this.rerenderPending);
                    gridElement = this.shadowRoot?.getElementById("gridElement");
                    this.grid = undefined;
                }
            }
            const width: number = ((this.previewSize == DashboardSizeOption.FULLSCREEN) ? this.clientWidth : (+(this.previewWidth?.replace(/\D/g, "")!)));
            const newPreset = getActivePreset(width, this.template.screenPresets!);
            if(this.activePreset && newPreset?.scalingPreset != this.activePreset?.scalingPreset) {
                if(!(recreate && force)) { // Fully rerender the grid by switching rerenderPending on and off, and continue after that.
                    if(!recreate) { // If not destroyed yet, destroy first.
                        this.grid?.destroy(false);
                    }
                    console.log("Recreating the grid after activePreset change.");
                    this.rerenderPending = true;
                    await this.updateComplete;
                    await this.waitUntil((_: any) => !this.rerenderPending);
                    gridElement = this.shadowRoot?.getElementById("gridElement");
                    this.grid = undefined;
                }
            }
            this.activePreset = newPreset;


            // If grid got reset, setup the ResizeObserver again.
            if(this.grid == null) {
                const gridHTML = this.shadowRoot?.querySelector(".maingrid");
                if(gridHTML) {
                    this.setupResizeObserver(gridHTML);
                }
            }
            this.grid = GridStack.init({
                acceptWidgets: (this.editMode),
                animate: true,
                cellHeight: (this.activePreset?.scalingPreset == DashboardScalingPreset.WRAP_TO_SINGLE_COLUMN ? (width / 4) : 'initial'),
                cellHeightThrottle: 100,
                column: this.template?.columns,
                disableOneColumnMode: (this.activePreset?.scalingPreset != DashboardScalingPreset.WRAP_TO_SINGLE_COLUMN),
                draggable: {
                    appendTo: 'parent', // Required to work, seems to be Shadow DOM related.
                    scroll: true
                },
                float: true,
                margin: 4,
                resizable: {
                    handles: 'all'
                },
                staticGrid: (this.activePreset?.scalingPreset == DashboardScalingPreset.WRAP_TO_SINGLE_COLUMN ? true : (!this.editMode)),
                styleInHead: false
            }, gridElement!);

            gridElement!.style.backgroundSize = "" + this.grid.cellWidth() + "px " + this.grid.getCellHeight() + "px";
            gridElement!.style.height = "100%";
            gridElement!.style.minHeight = "100%";

            this.grid.on('dropped', (_event: Event, _previousWidget: any, newWidget: GridStackNode | undefined) => {
                if(this.grid != null && newWidget != null) {
                    this.grid.removeWidget((newWidget.el) as GridStackElement, true, false); // Removes dragged widget first
                    this.createWidget(newWidget as ORGridStackNode);
                    this.dispatchEvent(new CustomEvent("dropped", { detail: newWidget }));
                }
            });
            this.grid.on('change', (_event: Event, items: any) => {
                if(this.template != null && this.template.widgets != null) {
                    console.log("Noticed a change in widget movement/sizing!");
                    (items as GridStackNode[]).forEach(node => {
                        const foundWidget: DashboardWidget | undefined = this.template?.widgets?.find(widget => { return widget.gridItem?.id == node.id; });
                        if(foundWidget && foundWidget.gridItem != null) {
                            foundWidget.gridItem.x = node.x;
                            foundWidget.gridItem.y = node.y;
                            foundWidget.gridItem.w = node.w;
                            foundWidget.gridItem.h = node.h;
                        }
                    });
                    console.log("Dispatching 'changed' event!");
                    this.dispatchEvent(new CustomEvent("changed", {detail: { template: this.template }}));
                }
            });
        }
    }

    // Method for creating Widgets (reused at many places)
    createWidget(gridStackNode: ORGridStackNode): DashboardWidget {
        const randomId = (Math.random() + 1).toString(36).substring(2);
        let displayName = generateWidgetDisplayName(this.template, gridStackNode.widgetType);
        if(displayName == undefined) { displayName = "Widget #" + randomId; } // If no displayName, set random ID as name.
        const gridItem: DashboardGridItem = generateGridItem(gridStackNode, displayName);

        const widget = {
            id: randomId,
            displayName: displayName,
            gridItem: gridItem,
            widgetType: gridStackNode.widgetType
        } as DashboardWidget;

        const tempTemplate = JSON.parse(JSON.stringify(this.template)) as DashboardTemplate;
        tempTemplate?.widgets?.push(widget);
        this.template = tempTemplate;
        this.dispatchEvent(new CustomEvent("changed", {detail: { template: this.template }}));
        return widget;
    }


    /* ------------------------------- */

    selectGridItem(gridItem: GridItemHTMLElement) {
        if(this.grid != null) {
            this.deselectGridItems(this.grid.getGridItems()); // deselecting all other items
            gridItem.querySelectorAll<HTMLElement>(".grid-stack-item-content").forEach((item: HTMLElement) => {
                item.classList.add('grid-stack-item-content__active'); // Apply active CSS class
            });
        }
    }
    deselectGridItem(gridItem: GridItemHTMLElement) {
        gridItem.querySelectorAll<HTMLElement>(".grid-stack-item-content").forEach((item: HTMLElement) => {
            item.classList.remove('grid-stack-item-content__active'); // Remove active CSS class
        });
    }

    deselectGridItems(gridItems: GridItemHTMLElement[]) {
        gridItems.forEach(item => {
            this.deselectGridItem(item);
        })
    }

    onGridItemClick(gridItem: DashboardGridItem) {
        if(!this.grid?.opts.staticGrid) {
            if(this.selectedWidget?.gridItem?.id == gridItem.id) {
                this.selectedWidget = undefined;
            } else {
                this.selectedWidget = this.template?.widgets?.find(widget => { return widget.gridItem?.id == gridItem.id; });
            }
        }
    }

    onFitToScreenClick() {
        const container = this.shadowRoot?.querySelector('#container');
        if(container) {
            const zoomWidth = +((0.95 * container.clientWidth) / +this.previewWidth!.replace('px', '')).toFixed(2);
            const zoomHeight = +((0.95 * container.clientHeight) / +this.previewHeight!.replace('px', '')).toFixed(2);
            if(zoomWidth > 1 && zoomHeight > 1) { this.previewZoom = 1; }
            else if(zoomWidth < zoomHeight) { this.previewZoom = zoomWidth; }
            else { this.previewZoom = zoomHeight; }
        }
    }

    // Render
    protected render() {
        return html`
                <div id="buildingArea" style="display: flex; flex-direction: column; height: 100%;" @click="${(event: PointerEvent) => { if((event.composedPath()[1] as HTMLElement).id === 'buildingArea') { this.selectedWidget = undefined; }}}">
                    ${this.editMode ? html`
                        <div id="view-options">
                            <or-mwc-input id="fit-btn" type="${InputType.BUTTON}" icon="fit-to-screen"
                                          @or-mwc-input-changed="${() => this.onFitToScreenClick()}">
                            </or-mwc-input>
                            <or-mwc-input id="zoom-input" type="${InputType.NUMBER}" outlined label="Zoom %" min="25" .value="${(this.previewZoom * 100)}" style="width: 90px"
                                          @or-mwc-input-changed="${(event: OrInputChangedEvent) => { this.previewZoom = event.detail.value / 100; }}"
                            ></or-mwc-input>
                            <or-mwc-input id="view-preset-select" type="${InputType.SELECT}" outlined label="Preset size" .value="${sizeOptionToString(this.previewSize!)}" .options="${[sizeOptionToString(DashboardSizeOption.LARGE), sizeOptionToString(DashboardSizeOption.MEDIUM), sizeOptionToString(DashboardSizeOption.SMALL), sizeOptionToString(DashboardSizeOption.CUSTOM)]}" style="min-width: 220px;"
                                          @or-mwc-input-changed="${(event: OrInputChangedEvent) => { this.previewSize = stringToSizeOption(event.detail.value); }}"
                            ></or-mwc-input>
                            <or-mwc-input id="width-input" type="${InputType.NUMBER}" outlined label="Width" min="100" .value="${this.previewWidth?.replace('px', '')}" style="width: 90px"
                                          @or-mwc-input-changed="${(event: OrInputChangedEvent) => { this.previewWidth = event.detail.value + 'px'; }}"
                            ></or-mwc-input>
                            <or-mwc-input id="height-input" type="${InputType.NUMBER}" outlined label="Height" min="100" .value="${this.previewHeight?.replace('px', '')}" style="width: 90px;"
                                          @or-mwc-input-changed="${(event: OrInputChangedEvent) => { this.previewHeight = event.detail.value + 'px'; }}"
                            ></or-mwc-input>
                            <or-mwc-input id="rotate-btn" type="${InputType.BUTTON}" icon="screen-rotation"
                                          @or-mwc-input-changed="${() => { const newWidth = this.previewHeight; const newHeight = this.previewWidth; this.previewWidth = newWidth; this.previewHeight = newHeight; }}">
                            </or-mwc-input>
                        </div>
                    ` : undefined}
                    ${this.rerenderPending ? html`
                        <div>
                            <span>Rendering Grid...</span>
                        </div>
                    ` : html`
                        <div id="container" style="display: flex; justify-content: center; height: 100%;">
                            ${this.activePreset?.scalingPreset == DashboardScalingPreset.BLOCK_DEVICE ? html`
                                <div style="position: absolute; z-index: 3; height: ${this.previewHeight}px; line-height: ${this.previewHeight}px; user-select: none;"><span>This dashboard does not support your device.</span></div>
                            ` : undefined}
                            <div class="maingrid ${this.previewSize == DashboardSizeOption.FULLSCREEN ? 'maingrid__fullscreen' : undefined}" style="width: ${this.previewWidth}; height: ${this.previewHeight}; visibility: ${this.activePreset?.scalingPreset == DashboardScalingPreset.BLOCK_DEVICE ? 'hidden' : 'visible'}; zoom: ${this.previewZoom}; -moz-transform: scale(${this.previewZoom}); transform-origin: top;">
                                <!-- Gridstack element on which the Grid will be rendered -->
                                <div id="gridElement" class="grid-stack ${this.previewSize == DashboardSizeOption.FULLSCREEN ? undefined : 'grid-element'}">
                                    ${this.template?.widgets ? repeat(this.template.widgets, (item) => item.id, (widget) => {
                                        return html`
                                            <div class="grid-stack-item" gs-id="${widget.gridItem?.id}" gs-x="${widget.gridItem?.x}" gs-y="${widget.gridItem?.y}" gs-w="${widget.gridItem?.w}" gs-h="${widget.gridItem?.h}" @click="${() => { this.onGridItemClick(widget.gridItem!); }}">
                                                <div class="grid-stack-item-content">
                                                    ${until(this.getWidgetContent(widget).then((content) => {
                                                        return content;
                                                    }))}
                                                </div>
                                            </div>
                                        `
                                    }) : undefined}
                                </div>
                            </div>
                        </div>
                    `}
                </div>
            `
    }

    setupResizeObserver(element: Element): ResizeObserver {
        console.log("Setting up ResizeObserver..");
        this.resizeObserver?.disconnect();
        this.resizeObserver = new ResizeObserver(() => {

            console.log("Noticed a Dashboard resize! Updating the grid..");
            console.log("Setting up Grid.. [#5]");
            this.setupGrid(true, false);

        });
        this.resizeObserver.observe(element);
        return this.resizeObserver;
    }

    /* --------------------------------------- */

    // Widget related methods such as getting Widget HTML,
    // or generating fake data for the widgets.


    async getWidgetContent(widget: DashboardWidget): Promise<TemplateResult> { //nosonar
        const _widget = Object.assign({}, widget);
        if(_widget.gridItem) {
            let assets: Asset[] = [];
            let attributes: [number, Attribute<any>][] = [];

            // Pulling data from database, however only when in editMode!!
            // KPI widgetType does use real data in EDIT mode as well, so separate check
            if(!this.editMode || _widget.widgetType == DashboardWidgetType.KPI) {
                const response = await manager.rest.api.AssetResource.queryAssets({
                    ids: widget.widgetConfig?.attributeRefs?.map((x: AttributeRef) => { return x.id; }) as string[]
                });
                console.warn("Getting attribute data from database!");
                assets = response.data;
                attributes = widget.widgetConfig?.attributeRefs?.map((attrRef: AttributeRef) => {
                    const assetIndex = assets.findIndex((asset) => asset.id === attrRef.id);
                    const foundAsset = assetIndex >= 0 ? assets[assetIndex] : undefined;
                    return foundAsset && foundAsset.attributes ? [assetIndex, foundAsset.attributes[attrRef.name!]] : undefined;
                }).filter((indexAndAttr: any) => !!indexAndAttr) as [number, Attribute<any>][];
            }

            switch (_widget.widgetType) {
                case DashboardWidgetType.CHART: {

                    // Generation of fake data when in editMode.
                    if(this.editMode) {
                        _widget.widgetConfig?.attributeRefs?.forEach((attrRef: AttributeRef) => {
                            if(!assets.find((asset: Asset) => { return asset.id == attrRef.id; })) {
                                assets.push({ id: attrRef.id, name: "Asset X", type: "ThingAsset" });
                            }
                        });
                        attributes = [];
                        _widget.widgetConfig?.attributeRefs?.forEach((attrRef: AttributeRef) => {
                            attributes.push([0, { name: attrRef.name }]);
                        });
                    }
                    return html`
                        <div class="gridItem">
                            <or-chart .assets="${assets}" .assetAttributes="${attributes}" .period="${widget.widgetConfig?.period}" 
                                      .dataProvider="${this.editMode ? (async (startOfPeriod: number, endOfPeriod: number, _timeUnits: any, _stepSize: number) => { return this.generateMockData(_widget, startOfPeriod, endOfPeriod, 20); }) : undefined}"
                                      showLegend="${(_widget.widgetConfig?.showLegend != null) ? _widget.widgetConfig?.showLegend : true}" .realm="${this.realm}" .showControls="${_widget.widgetConfig?.showTimestampControls}" style="height: 100%"
                            ></or-chart>
                        </div>
                    `;
                }

                case DashboardWidgetType.KPI: {
                    return html`
                        <div class='gridItem' style="display: flex;">
                            <!--<or-map center='5.454250, 51.445990' zoom='5' style='height: 100%; width: 100%;'></or-map>-->
                            <or-attribute-card .assets="${assets}" .assetAttributes="${attributes}" .period="${widget.widgetConfig?.period}"
                                               showControls="${false}" .realm="${this.realm}" style="height: 100%;"
                            ></or-attribute-card>
                        </div>
                    `;
                }
            }
        }
        return html`<span>Error!</span>`;
    }

    protected generateMockData(widget: DashboardWidget, startOfPeriod: number, _endOfPeriod: number, amount: number = 10): any {
        switch (widget.widgetType) {
            case DashboardWidgetType.CHART: {
                const mockTime: number = startOfPeriod;
                const chartData: any[] = [];
                const interval = (Date.now() - startOfPeriod) / amount;

                // Generating random coordinates on the chart
                let data: any[] = [];
                widget.widgetConfig?.attributeRefs?.forEach((_attrRef: AttributeRef) => {
                    let valueEntries: any[] = [];
                    let prevValue: number = 100;
                    for(let i = 0; i < amount; i++) {
                        const value = Math.floor(Math.random() * ((prevValue + 2) - (prevValue - 2)) + (prevValue - 2))
                        valueEntries.push({
                            x: (mockTime + (i * interval)),
                            y: value
                        });
                        prevValue = value;
                    }
                    data.push(valueEntries);
                })

                // Making a line for each attribute
                widget.widgetConfig?.attributeRefs?.forEach((attrRef: AttributeRef) => {
                    chartData.push({
                        backgroundColor: ["#3869B1", "#DA7E30", "#3F9852", "#CC2428", "#6B4C9A", "#922427", "#958C3D", "#535055"][chartData.length],
                        borderColor: ["#3869B1", "#DA7E30", "#3F9852", "#CC2428", "#6B4C9A", "#922427", "#958C3D", "#535055"][chartData.length],
                        data: data[chartData.length],
                        fill: false,
                        label: attrRef.name,
                        pointRadius: 2
                    });
                });
                return chartData;
            }
        }
        return [];
    }
}
