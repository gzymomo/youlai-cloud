package com.youlai.system.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.IService;
import com.youlai.system.pojo.entity.SysDict;
import com.youlai.system.pojo.form.DictItemForm;
import com.youlai.system.pojo.query.DictItemPageQuery;
import com.youlai.system.pojo.vo.dict.DictItemPageVO;
import com.youlai.common.web.domain.Option;

import java.util.List;


/**
 * 字典数据项业务接口层
 *
 * @author haoxr
 * @date 2022/6/9
 */
public interface SysDictService extends IService<SysDict> {

    /**
     * 字典数据项分页列表
     *
     * @param queryParams
     * @return
     */
    Page<DictItemPageVO> listDictItemPages(DictItemPageQuery queryParams);

    /**
     * 字典数据项表单详情
     *
     * @param id 字典数据项ID
     * @return
     */
    DictItemForm getDictItemFormData(Long id);

    /**
     * 新增字典数据项
     *
     * @param dictItemForm 字典数据项表单
     * @return
     */
    boolean saveDictItem(DictItemForm dictItemForm);

    /**
     * 修改字典数据项
     *
     * @param id           字典数据项ID
     * @param dictItemForm 字典数据项表单
     * @return
     */
    boolean updateDictItem(Long id, DictItemForm dictItemForm);

    /**
     * 删除字典数据项
     *
     * @param idsStr 字典数据项ID，多个以英文逗号(,)分割
     * @return
     */
    boolean deleteDictItems(String idsStr);

    /**
     * 根据字典类型编码获取字典数据项
     *
     * @param typeCode 字典类型编码
     * @return
     */
    List<Option> listDictItemsByTypeCode(String typeCode);
}
