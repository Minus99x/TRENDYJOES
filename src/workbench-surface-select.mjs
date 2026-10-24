import {assertWorkbenchDraft,nextWorkbenchDraft} from './workbench-draft-state.mjs';
export function selectWorkbenchSurface(d,surfaceId){assertWorkbenchDraft(d);if(!d.surfaces.includes(surfaceId))throw new TypeError('WORKBENCH_UNKNOWN_SURFACE');return d.activeSurface===surfaceId?d:nextWorkbenchDraft(d,{activeSurface:surfaceId});}
